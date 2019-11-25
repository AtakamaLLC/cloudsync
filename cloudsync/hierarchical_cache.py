import logging
from typing import Dict, Optional, Tuple, Set, Generator, Union, Type
from cloudsync.provider import Provider
from cloudsync import OType, DIRECTORY, FILE
from enum import Enum
import weakref

log = logging.getLogger(__name__)


class Casing(Enum):
    SENSITIVE = "sensitive"
    INSENSITIVE = "insensitive"


class Node:
    def __init__(self, provider, otype: OType, oid, name, parent, metadata: Dict[str, any]):
        self._oid = None
        self.oid = oid
        self.parent = parent
        self.name = name
        self.metadata = metadata or {}
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
    def __init__(self, provider: Provider, root_oid,
                 metadata_template: Optional[Dict[str, Type]] = None, root_metadata: Optional[Dict[str, any]] = None):
        self._metadata_template = metadata_template or {}
        self._root = self.new_node(provider, DIRECTORY, root_oid, '', None, root_metadata)
        self._oid_to_node: Dict[str, Node] = {self._root.oid: self._root}
        self._provider = provider

    def new_node(self, provider, otype: OType, oid, name, parent, metadata: Dict[str, any]):
        self.check_metadata(metadata)
        return Node(provider=provider, otype=otype, oid=oid, name=name, parent=parent, metadata=metadata)

    def check_metadata(self, metadata: Optional[Dict[str, any]]) -> None:
        if metadata is None:
            return
        for k, v in metadata.items():
            if k not in self._metadata_template:
                raise ValueError("key %s:%s is in metadata, but not in the template", k, v)
            if not isinstance(v, self._metadata_template.get(k, None)):
                raise ValueError("key %s:%s has the wrong type. provided %s, template has %s",
                                 k, v, type(v), self._metadata_template.get(k, None))

    def get_metadata(self, *, path=None, oid=None) -> any:
        node = self._get_node(path=path, oid=oid)
        if node:
            return node.metadata
        return None

    def set_metadata(self, metadata, path=None, oid=None):
        self.check_metadata(metadata)
        node = self._get_node(path=path, oid=oid)
        if node:
            node.metadata = metadata or {}

    def update(self, path, otype, oid=None, metadata=None, keep=True):
        self._update(path=path, otype=otype, oid=oid, metadata=metadata, keep=keep)

    def _update(self, path, otype, oid=None, metadata=None, keep=True):
        metadata = metadata or {}
        self.check_metadata(metadata)
        node = self._get_node(path=path)
        if node and node.type != otype:
            self._delete(remove_node=node)
            node = None
        if node is None:
            self.__make_node(otype=otype, path=path, oid=oid, metadata=metadata)
            return node
        if oid or not keep:
            self.set_oid(path, oid)
        if keep:
            old_metadata = node.metadata
            old_metadata.update(metadata)
        else:
            self.set_metadata(metadata, path=path)

    def __insert_node(self, node: Node, path: str):
        parent_path, name = self.split(path)
        parent_node = self._get_node(path=parent_path)
        if parent_node is None or parent_node.type == FILE:
            parent_node = self._mkdir(parent_path, None)

        node.name = name
        # note: the type of parent is now ProxyType, not Node, because of the weakref.proxy()
        node.parent = weakref.proxy(parent_node)

        self.delete(path=path)
        if node.oid:
            self.delete(oid=node.oid)

        parent_node.children[name] = node

        for current_node, current_path in self._walk(node):
            if current_node.oid:
                possible_conflict = self._oid_to_node.get(current_node.oid)
                if id(possible_conflict) != id(current_node):
                    self.delete(oid=current_node.oid)
                self._oid_to_node[current_node.oid] = current_node

    def __make_node(self, otype: OType, path: str, oid: Optional[str], metadata: Optional[Dict[str, any]] = None):
        norm_path = self._provider.normalize_path(path)

        _, name = self._provider.split(path)
        new_node = self.new_node(self._provider, otype, oid, name, None, metadata)
        self.__insert_node(new_node, norm_path)
        return new_node

    def _walk(self, node: Node, path: str = None) -> Generator[Node, None, None]:
        if not path:
            path = node.full_path()
        assert node
        yield (node, path)
        if node.type == FILE:
            return
        for child_name, child_node in node.children.items():
            child_path = self.join(path, child_name)
            if child_node.type == DIRECTORY:
                yield from self._walk(child_node, child_path)
            else:
                yield (child_node, child_path)

    def walk(self, *, oid: str = None, path: str = None) -> Generator[str, None, None]:
        if not (oid or path):
            path = self._provider.sep
        node = self._get_node(oid=oid, path=path)
        if node is None:
            return None
        for curr_node, curr_path in self._walk(node):
            yield curr_path

    def listdir(self, *, oid: str = None, path: str = None):
        node = self._get_node(oid=oid, path=path)
        if not node:
            return []
        return [x.name for x in node.children.values()]

    def mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, any]] = None):
        self._mkdir(path, oid, metadata)

    def _mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, any]] = None) -> Node:
        new_node = self.__make_node(DIRECTORY, path, oid, metadata)
        return new_node

    def create(self, path: str, oid: str, metadata: Optional[Dict[str, any]] = None):
        self._create(path, oid, metadata)

    def _create(self, path: str, oid: str, metadata: Optional[Dict[str, any]] = None):
        return self.__make_node(FILE, path, oid, metadata=metadata)

    def delete(self, *, oid: str = None, path: str = None):
        node = self._get_node(oid=oid, path=path)
        if node:
            # Recursively delete the children to ensure they are popped from the oid_to_node dict
            if node.type == DIRECTORY:
                for child_node in list(node.children.values()):
                    self.delete(oid=child_node.oid, path=child_node.full_path())
            self._delete(node)

    def _delete(self, remove_node):
        if not remove_node or remove_node.oid == self._root.oid:
            return None
        node_deleted_from_parent = None
        try:
            node_deleted_from_parent = remove_node.parent.children.pop(remove_node.name)
        except KeyError:
            pass

        for curr_node, curr_path in self._walk(remove_node):
            curr_node: Node
            if curr_node.oid:
                self._oid_to_node.pop(curr_node.oid, None)

        if node_deleted_from_parent:
            if id(node_deleted_from_parent) != id(remove_node):
                if node_deleted_from_parent.oid is not None:
                    self._oid_to_node.pop(node_deleted_from_parent.oid)
                raise LookupError("Structure problem in hierarchical cache. %s != %s", node_deleted_from_parent, remove_node)

        remove_node.parent = None

        return remove_node

    def split(self, path: str) -> Tuple[str, str]:
        stripped_path = path.rstrip(self._provider.sep + self._provider.alt_sep)
        return self._provider.split(stripped_path)

    def join(self, *paths):
        return self._provider.join(*paths)

    def rename(self, old_path: str, new_path: str):
        self._rename(old_path, new_path)

    def _rename(self, old_path: str, new_path: str) -> Optional[Node]:
        if old_path in (self._provider.sep, self._provider.alt_sep):
            raise ValueError("cannot rename '%s'" % (self._provider.sep, ))
        node = self._get_node(path=old_path)
        self._delete(node)  # _delete will delete the parent but not the children
        self.delete(path=new_path)  # renaming a nonexistent oid over an existing path should kick the target out of the tree
        if node:
            self.__insert_node(node, new_path)
        return node

    def _unsafe_path_to_node(self, path):
        if path in (self._provider.sep, self._provider.alt_sep):
            return self._root
        parent_path, name = self._provider.split(path)
        parent_node = self._unsafe_path_to_node(parent_path)
        return parent_node.children.get(name) if parent_node else None

    def _get_node(self, *, oid: str = None, path: str = None) -> Node:
        if oid is not None:
            if oid == self._root.oid:
                return self._root
            return self._oid_to_node.get(oid)
        elif path is not None:
            norm_path = self._provider.normalize_path(path)
            if norm_path in (self._provider.sep, self._provider.alt_sep):
                return self._root
            if len(norm_path) > 0 and norm_path[0] in (self._provider.sep, self._provider.alt_sep):
                return self._unsafe_path_to_node(norm_path)
            raise ValueError('Path must be fully qualified path (begin with %s)' % (self._provider.sep, ))
        else:
            raise ValueError('get_node requires an oid or path')

    def set_oid(self, path: str, oid: str):
        node = self._get_node(path=path)
        if not node:
            return
        if node.oid != oid:
            if node.oid:
                self.delete(oid=oid)
            node.oid = oid
            self.__insert_node(node, path)

    def get_oid(self, path):
        node = self._get_node(path=path)
        return node.oid if node else None

    def get_path(self, oid):
        node = self._oid_to_node.get(oid)
        return node.full_path() if node else None

    def get_type(self, *, oid=None, path=None) -> Optional[OType]:
        node = self._get_node(oid=oid, path=path)
        return node.type if node else None

    def __iter__(self):
        return self.walk()
