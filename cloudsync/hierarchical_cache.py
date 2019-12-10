import logging
from typing import Dict, Optional, Tuple, Generator, Type, List, Any
from enum import Enum
import weakref
from pystrict import strict
from cloudsync.provider import Provider
from cloudsync import OType, DIRECTORY, FILE

log = logging.getLogger(__name__)


class Casing(Enum):
    SENSITIVE = "sensitive"
    INSENSITIVE = "insensitive"


@strict
class Node:
    def __init__(self, provider: Provider, otype: OType, oid: Optional[str], name: str, parent: 'Node', metadata: Dict[str, Any]):
        self._oid = oid
        self.parent = parent
        self.wr_parent: Optional[weakref.ReferenceType] = None
        self.name = name
        self.metadata = metadata or {}
        self._provider = provider
        self.children: Dict[str, Node] = {}
        self.type: OType = otype

    def _real_parent_ref(self):
        return self.wr_parent()  # pylint: disable=not-callable

    def check(self):
        if self.parent:
            if self.oid is not None and self.oid == self.parent.oid:
                if self._real_parent_ref() is self:
                    log.error("parent is self! oid=%s name=%s", self.oid, self.name)
                else:
                    log.error("parent is not self: oid=%s name=%s parent=-->%s<-- path=%s", self.oid, self.name, self.parent, "")
            assert self.oid is None or self.oid != self.parent.oid
            assert self._real_parent_ref() is not self

    @property
    def oid(self):
        return self._oid

    @oid.setter
    def oid(self, val):
        self.check()
        assert self._oid is None or val is not None
        self._oid = val

    def full_path(self):
        return self._full_path([])

    def _full_path(self, seen: List['Node']):
        if self in seen:
            log.error("hierarchical cache loop at node name=%s oid=%s", self.name, self.oid)
            for node in seen:
                if node is not self:
                    log.error("other node: name=%s, oid=%s", node.name, node.oid)
        seen.append(self)
        self.check()
        if self.parent is None:
            return self._provider.sep
        return self._provider.join(self.parent._full_path(seen), self.name)  # pylint: disable=protected-access

    def add_child(self, child_node):
        self.check()
        child_node.check()
        assert self.type == DIRECTORY
        self.children += [child_node]

    def __str__(self):
        return f"{type(self)} {self.oid}:{self.full_path()} {self.metadata or ''}"


@strict
class HierarchicalCache:
    def __init__(self, provider: Provider, root_oid: Any,
                 metadata_template: Optional[Dict[str, Type]] = None, root_metadata: Optional[Dict[str, Any]] = None):
        assert root_oid is not None
        self._oid_type = type(root_oid)
        self._metadata_template = metadata_template or {}
        self._provider: Provider = provider
        self._root: Node = self.new_node(DIRECTORY, root_oid, '', None, root_metadata)
        self._oid_to_node: Dict[str, Node] = {self._root.oid: self._root}

    def check(self, node: Node):
        if node.oid is not None:
            assert type(node.oid) is self._oid_type, \
                "oid type %s does not match the root oid type %s" % (type(node.oid), self._oid_type)
        node.full_path()
        node.check()

    def new_node(self, otype: OType, oid, name, parent, metadata: Dict[str, Any]) -> Node:
        self._check_metadata(metadata)
        retval = Node(provider=self._provider, otype=otype, oid=oid, name=name, parent=parent, metadata=metadata)
        retval.check()
        self.check(retval)
        return retval

    def _check_metadata(self, metadata: Optional[Dict[str, Any]]) -> None:
        if metadata is None:
            return
        for k, v in metadata.items():
            if k not in self._metadata_template:
                raise ValueError("key %s:%s is in metadata, but not in the template" % (k, v))
            if not isinstance(v, self._metadata_template.get(k, None)):
                raise ValueError("key %s:%s has the wrong type. provided %s, template has %s" %
                                 (k, v, type(v), self._metadata_template.get(k, None)))

    def get_metadata(self, *, path=None, oid=None) -> Dict:
        node = self._get_node(path=path, oid=oid)
        if node:
            return node.metadata
        return None

    def set_metadata(self, metadata, *, path=None, oid=None):
        self._check_metadata(metadata)
        node = self._get_node(path=path, oid=oid)
        if node:
            node.metadata = metadata or {}

    def update(self, path, otype, oid=None, metadata=None, keep=True):
        node = self._update(path=path, otype=otype, oid=oid, metadata=metadata, keep=keep)
        if node:
            node.check()
            self.check(node)

    def _update(self, path, otype, oid=None, metadata=None, keep=True) -> Node:
        metadata = metadata or {}
        self._check_metadata(metadata)
        node = self._get_node(path=path)
        if node and node.type != otype:
            self._delete(remove_node=node)
            node = None
        if node is None:
            node = self.__make_node(otype=otype, path=path, oid=oid, metadata=metadata)
            return node
        if oid or not keep:
            self.set_oid(path, oid)
        if keep:
            old_metadata = node.metadata
            old_metadata.update(metadata)
        else:
            self.set_metadata(metadata, path=path)
        return node

    def __insert_node(self, node: Node, path: str):
        parent_path, name = self.split(path)
        parent_node = self._get_node(path=parent_path)
        if parent_node is None or parent_node.type == FILE:
            parent_node = self._mkdir(parent_path, None)

        node.name = name
        # note: the type of parent is now ProxyType, not Node, because of the weakref.proxy()
        assert parent_node is not node
        node.parent = weakref.proxy(parent_node)
        node.wr_parent = weakref.ref(parent_node)

        self.delete(path=path)
        if node.oid:
            self.delete(oid=node.oid)

        parent_node.children[name] = node

        for current_node, _ignored_current_path in self._walk(node):
            if current_node.oid:
                possible_conflict = self._oid_to_node.get(current_node.oid)
                if id(possible_conflict) != id(current_node):
                    self.delete(oid=current_node.oid)
                self._oid_to_node[current_node.oid] = current_node

    def __make_node(self, otype: OType, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> Node:
        norm_path = self._provider.normalize_path(path)

        _, name = self._provider.split(path)
        new_node = self.new_node(otype, oid, name, None, metadata)
        self.__insert_node(new_node, norm_path)
        self.check(new_node)
        return new_node

    def _walk(self, node: Node, path: str = None) -> Generator[Tuple[Node, str], None, None]:
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
            return
        for _ignored_curr_node, curr_path in self._walk(node):
            yield curr_path

    def listdir(self, *, oid: str = None, path: str = None):
        node = self._get_node(oid=oid, path=path)
        if not node:
            return []
        return [x.name for x in node.children.values()]

    def mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None):
        self._mkdir(path, oid, metadata)

    def _mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> Node:
        new_node = self.__make_node(DIRECTORY, path, oid, metadata)
        return new_node

    def create(self, path: str, oid: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self._create(path, oid, metadata)

    def _create(self, path: str, oid: str, metadata: Optional[Dict[str, Any]] = None) -> Node:
        return self.__make_node(FILE, path, oid, metadata=metadata)

    def delete(self, *, oid: str = None, path: str = None):
        node = self._get_node(oid=oid, path=path)
        if node:
            # Recursively delete the children to ensure they are popped from the oid_to_node dict
            if node.type == DIRECTORY:
                children = list(node.children.values())
                for child_node in children:
                    log.debug("about to delete child %s:%s", child_node.oid, child_node.full_path())
                    self.delete(oid=child_node.oid, path=child_node.full_path())
            log.debug("about to delete parent %s:%s", node.oid, node.full_path())
            self._delete(node)

    def _delete(self, remove_node):
        if not remove_node or remove_node.oid == self._root.oid:
            return None
        node_deleted_from_parent = None
        try:
            node_deleted_from_parent = remove_node.parent.children.pop(remove_node.name)
        except KeyError:
            pass

        curr_node: Node
        for curr_node, _ignored_curr_path in self._walk(remove_node):
            if curr_node.oid:
                self._oid_to_node.pop(curr_node.oid, None)

        if node_deleted_from_parent:
            if id(node_deleted_from_parent) != id(remove_node):
                if node_deleted_from_parent.oid is not None:
                    self._oid_to_node.pop(node_deleted_from_parent.oid)
                raise LookupError("Structure problem in hierarchical cache. %s != %s" %
                                  (node_deleted_from_parent, remove_node))

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
            self.check(node)
        return node

    def _unsafe_path_to_node(self, path: str) -> Node:
        # this method is "unsafe" because it depends on sanitizing the arguments
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

    def set_oid(self, path: str, oid: str, otype: OType = None):
        node = self._get_node(path=path)
        if not node:
            if otype:
                self.__make_node(otype, path, oid)
            return
        if node.oid != oid:
            if node.oid:
                self.delete(oid=oid)
            self.__insert_node(node, path)
            node.oid = oid
            self.check(node)

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
