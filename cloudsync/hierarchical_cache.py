import logging
from typing import Type, Dict, Optional, Tuple, Set, Generator, Union
from cloudsync.provider import Provider
from cloudsync import OType, DIRECTORY, FILE
from enum import Enum

log = logging.getLogger(__name__)


class Casing(Enum):
    SENSITIVE="sensitive"
    INSENSITIVE="insensitive"


class Node:
    def __init__(self, provider, otype: OType, oid, name, parent, metadata: Optional[Dict[str, any]]):
        self._oid = None
        self.oid = oid
        self.parent = parent
        self.name = name
        self.metadata = metadata
        self._provider = provider
        self.children = {}
        self.type: OType = otype

    @property
    def oid(self):
        return self._oid

    @oid.setter
    def oid(self, val):
        if self._oid is not None and val is None:
            log.error('what?')
        self._oid = val

    def full_path(self):
        if self.parent is None:
            return self._provider.sep
        return self._provider.join(self.parent.full_path(), self.name)

    def add_child(self, child_node):
        assert self.type == DIRECTORY
        self.children += [child_node]

    def __str__(self):
        return f"{type(self)} {self.oid}:{self.full_path()} {self.metadata or ''}"


class HierarchicalCache:
    def __init__(self, provider: Provider, root_oid, metadata_fields: Optional[Set[str]] = None):
        metadata_fields = metadata_fields or set()
        self.root = Node(provider, DIRECTORY, root_oid, '', None, dict.fromkeys(metadata_fields))
        self._oid_to_node: Dict[str, Node] = {self.root.oid: self.root}
        self._metadata_fields = metadata_fields or set()
        self._provider = provider

    def __insert_node(self, node: Node, path: str):
        parent_path, name = self.split(path)
        parent_node = self._get_node(path=parent_path)
        if parent_node is None or parent_node.type == FILE:
            parent_node = self._mkdir(parent_path, None)

        node.name = name
        node.parent = parent_node
        parent_node.children[name] = node

        if node.oid:
            if self._oid_to_node.get(node.oid):
                self.delete(node.oid)
            self._oid_to_node[node.oid] = node

    def __make_node(self, otype: OType, path: str, oid: Optional[str], metadata: Optional[Dict[str, any]] = None):
        norm_path = self._provider.normalize_path(path)

        new_metadata = dict.fromkeys(self._metadata_fields)
        new_metadata.update(metadata or {})
        if ((metadata and not (len(metadata) == len(new_metadata) == len(self._metadata_fields))) or
                (not metadata and len(self._metadata_fields) > 0)):
            log.warning("metadata for node does not match metadata fields template: %s %s!=%s",
                        norm_path, metadata.keys(), self._metadata_fields)

        new_node = Node(self._provider, otype, oid, None, None, new_metadata)
        self.__insert_node(new_node, norm_path)
        return new_node

    def walk(self, oid: str = None, path: str = None, _node: Node = None) -> Generator[str, None, None]:
        if not _node:
            if oid:
                _node = self._get_node(oid=oid)
            elif path:
                _node = self._get_node(path=path)
            else:
                _node = self.root
        if _node is None:
            return None
        if path is None:
            path = _node.full_path()
        yield path
        if _node.type == FILE:
            return
        for child_name, child_node in _node.children.items():
            child_path = self.join(path, child_name)
            if child_node.type == DIRECTORY:
                yield from self.walk(_node=child_node, path=child_path)
            else:
                yield child_path

    def listdir(self, oid: str = None, path: str = None):
        node = self._get_node(oid=oid, path=path)
        if not node:
            return []
        return [x.name for x in node.children]

    def mkdir(self, path: str, oid: Optional[str]):
        self._mkdir(path, oid)

    def _mkdir(self, path: str, oid: Optional[str]) -> Node:
        new_node = self.__make_node(DIRECTORY, path, oid)
        return new_node

    def create(self, path: str, oid: str):
        self._create(path, oid)

    def _create(self, path: str, oid: str):
        return self.__make_node(FILE, path, oid)

    def delete(self, oid: str) -> Optional[Node]:
        return self._delete(oid) is not None

    def _delete(self, oid: str) -> Optional[Node]:
        remove_node = self._oid_to_node.get(oid)
        if not remove_node or remove_node.oid == self.root.oid:
            return None
        node_deleted_from_parent = None
        try:
            node_deleted_from_parent = remove_node.parent.children.pop(remove_node.name)
        except KeyError:
            pass
        if node_deleted_from_parent:
            if id(node_deleted_from_parent) != id(remove_node):
                raise LookupError("Structure problem in hierarchical cache. %s != %s", node_deleted_from_parent, remove_node)
            self._oid_to_node.pop(remove_node.oid)
        return remove_node

    def split(self, path: str) -> Tuple[str, str]:
        stripped_path = path.rstrip(self._provider.sep + self._provider.alt_sep)
        return self._provider.split(stripped_path)

    def join(self, *paths):
        return self._provider.join(*paths)

    def rename(self, oid: str, path: str) -> bool:
        return self._rename(oid, path) is not None

    def _rename(self, oid: str, path: str) -> Optional[Node]:
        if oid == self.root.oid:
            raise ValueError("cannot rename '%s'" % (self._provider.sep, ))
        node = self._delete(oid)
        if not node:
            return None
        self.__insert_node(node, path)
        return node

    def _unsafe_path_to_node(self, path):
        if path in (self._provider.sep, self._provider.alt_sep):
            return self.root
        parent_path, name = self._provider.split(path)
        parent_node = self._unsafe_path_to_node(parent_path)
        return parent_node.children.get(name) if parent_node else None

    # def _old_unsafe_path_to_node(self, path, node):
    #     if self._provider.sep not in path:
    #         return node.children.get(path)
    #     next_node_name, next_path = path.split(self._provider.sep, 1)
    #     logging.error(f'Path is {path}, next node name is {next_node_name}, next path is {next_path}')
    #     next_node = node.children.get(next_node_name)
    #     if next_node is None:
    #         return None
    #     return self._unsafe_path_to_node(next_path, next_node)

    def _get_node(self, oid: str = None, path: str = None) -> Node:
        if oid is not None:
            if oid == self.root.oid:
                return self.root
            return self._oid_to_node.get(oid)
        elif path is not None:
            norm_path = self._provider.normalize_path(path)
            if norm_path in (self._provider.sep, self._provider.alt_sep):
                return self.root
            if len(norm_path) > 0 and norm_path[0] in (self._provider.sep, self._provider.alt_sep):
                return self._unsafe_path_to_node(norm_path)
            raise ValueError('Path must be fully qualified path (begin with %s)' % (self._provider.sep, ))
        else:
            raise ValueError('get_node requires an oid or path')

    def get_oid(self, path):
        node = self._get_node(path=path)
        return node.oid if node else None

    # def _backtrace_path(self, current_node):
    #     if current_node.oid == self.root.oid:
    #         return ''
    #     return self._backtrace_path(current_node.parent) + self.sep + current_node.name

    def get_path(self, oid):
        node = self._oid_to_node.get(oid)
        if not node:
            return None
        return node.full_path()

    def get_type(self, oid=None, path=None) -> Optional[OType]:
        assert oid or path
        if path and not oid:
            oid = self.get_oid(path)
        if not oid:
            return None
        node = self._oid_to_node.get(oid)
        return node

    def __iter__(self):
        return self.walk()
