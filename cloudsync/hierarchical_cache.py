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
    """
    Represents one component of a path in the hierarchical cache of paths and oids.
    """
    def __init__(self, provider: Provider, otype: OType, oid: Optional[str],  # pylint: disable=too-many-arguments
                 name: str, parent: 'Node', metadata: Dict[str, Any], is_root: bool = False):
        self._oid = oid
        self.wr_parent: Optional[weakref.ReferenceType] = None
        if parent:
            self.wr_parent = weakref.ref(parent)
        self.name = name
        self.metadata = metadata or {}
        self._provider = provider
        self.children: Dict[str, Node] = {}
        self.type: OType = otype
        self.is_root = is_root

    @property
    def parent(self):
        return self.wr_parent() if self.wr_parent else None

    @parent.setter
    def parent(self, value):
        self.wr_parent = weakref.ref(value) if value else None

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
        elements = self._full_path_nodes([])
        if not elements[0].is_root:
            return None
        names = [x.name for x in elements]
        return self._provider.join(*names)

    def _full_path_nodes(self, seen: List['Node']):
        """
        Recursively walks up my tree to get my full path, asserting that we don't have cycles.
        """
        if self in seen:
            log.error("hierarchical cache loop at node name=%s oid=%s", self.name, self.oid)
            for node in seen:
                if node is not self:
                    log.error("other node: name=%s, oid=%s", node.name, node.oid)
        seen.append(self)
        self.check()
        parent = self.parent
        if parent:
            # noinspection PyProtectedMember
            return parent._full_path_nodes(seen)  # pylint: disable=protected-access
        else:
            seen.reverse()  # This must only happen once at the end of the recursion
            return seen

    def add_child(self, child_node: 'Node'):
        self.check()
        child_node.check()
        assert self.type == DIRECTORY
        self.children[child_node.name] = child_node

    def __str__(self):
        return f"{type(self)} {self.oid}:{self.full_path()} {self.metadata or ''}"


@strict
class HierarchicalCache:
    """
    Use this to cache path->oid and oid->path mappings.   Has nice helpers for clearing cache entries in response to provider-like functions.

    Also allows metadata to be stored alongside each entry.
    """
    def __init__(self, provider: Provider, root_oid: Any,
                 metadata_template: Optional[Dict[str, Type]] = None, root_metadata: Optional[Dict[str, Any]] = None):
        assert root_oid is not None
        self._oid_type = type(root_oid)
        self._metadata_template = metadata_template or {}
        self._provider: Provider = provider
        self._root: Node = self._new_node(DIRECTORY, root_oid, '', None, root_metadata, is_root=True)
        self._oid_to_node: Dict[str, Node] = {self._root.oid: self._root}

    def _check(self, node: Node):
        node.check()
        if node.oid is not None:
            assert type(node.oid) is self._oid_type, \
                "oid type %s does not match the root oid type %s" % (type(node.oid), self._oid_type)
        node.full_path()
        node.check()

    def _new_node(self, otype: OType, oid, name, parent, metadata: Dict[str, Any], is_root=False) -> Node:
        self._check_metadata(metadata)
        retval = Node(provider=self._provider, otype=otype, oid=oid, name=name, parent=parent, metadata=metadata, is_root=is_root)
        retval.check()
        self._check(retval)
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

    def get_metadata(self, *, path=None, oid=None) -> Optional[Dict]:
        """
        Retrives the metadata for a node at oid, if oid is not set, retrieves metadata for path instead
        Args:
              path: the target path
              oid: the target oid
        Returns:
              Optional[Dict]: metadata for the specified node
        """
        node = self._get_node(path=path, oid=oid)
        if node:
            return node.metadata
        return None

    def set_metadata(self, metadata, *, path=None, oid=None):
        """
        Sets the metadata for the node at oid, if oid is not set, sets the metadata for the node at path instead
        Metadata must conform to the metadata template passed in on construction
        Args:
              metadata: dictionary containing the new metadata entries
              path: the target path
              oid: the target oid
        """
        self._check_metadata(metadata)
        node = self._get_node(path=path, oid=oid)
        if node:
            node.metadata = metadata or {}

    def update(self, path, otype, oid=None, metadata=None, keep=True):
        """
        Updates a node in the cache.
        NOTE: the node passed in may not be the same as the node returned
        Args:
              path: the path to update
              otype: if otype for the node changes, the old node is deleted and a new is added in its place
              oid: the new oid, if oid for the node changes the old is delete anda  new is added
              metadata: the metadata dictionary to add to the node
              keep: if set the metadata is added to the old, else it replaces it
        Returns:
              Node: the updated node, returned because it may not be the same as the passed node
        """
        node = self._update(path=path, otype=otype, oid=oid, metadata=metadata, keep=keep)
        if node:
            self._check(node)

    def _update(self, path, otype: OType, oid=None, metadata=None, keep=True) -> Node:
        metadata = metadata or {}
        self._check_metadata(metadata)
        node = self._get_node(path=path)
        if node and node.type != otype:
            self._delete(remove_node=node)
            node = None
        if node is None:
            node = self.__make_node(otype=otype, path=path, oid=oid, metadata=metadata)
            return node
        if oid:
            self._set_oid(node, oid)
        if keep:
            old_metadata = node.metadata
            old_metadata.update(metadata)
        else:
            self.set_metadata(metadata, path=path)
        return node

    def __insert_node(self, node: Node, path: str):
        parent_path, name = self._split(path)
        parent_node = self._get_node(path=parent_path)
        if parent_node is None or parent_node.type == FILE:
            parent_node = self._mkdir(parent_path, None)

        node.name = name
        # note: the type of parent is now ProxyType, not Node, because of the weakref.proxy()
        assert parent_node is not node
        node.wr_parent = weakref.ref(parent_node)

        self.delete(path=path)
        if node.oid:
            self.delete(oid=node.oid)

        parent_node.add_child(node)

        for current_node, _ignored_current_path in self._walk(node):
            if current_node.oid:
                possible_conflict = self._oid_to_node.get(current_node.oid)
                if id(possible_conflict) != id(current_node):
                    self.delete(oid=current_node.oid)
                self._oid_to_node[current_node.oid] = current_node

    def __make_node(self, otype: OType, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> Node:
        norm_path = self._provider.normalize_path(path)

        _, name = self._provider.split(path)
        new_node = self._new_node(otype, oid, name, None, metadata)
        self.__insert_node(new_node, norm_path)
        self._check(new_node)
        return new_node

    def _walk(self, node: Node, path: str = None) -> Generator[Tuple[Node, str], None, None]:
        if not path:
            path = node.full_path()
        assert node
        yield node, path
        if node.type == FILE:
            return
        for child_name, child_node in node.children.items():
            child_path = self._provider.join(path, child_name)
            if child_node.type == DIRECTORY:
                yield from self._walk(child_node, child_path)
            else:
                yield child_node, child_path

    def walk(self, *, oid: str = None, path: str = None) -> Generator[str, None, None]:
        """
        Walks the cache depth first from the node specified by oid. if oid is not set walks the node specified by path
        Args:
              oid: the target oid
              path: the target path
        Returns:
              Generator[str]: a generator for all node names from the input nodes children
        """
        if not (oid or path):
            path = self._root.full_path()
        node = self._get_node(oid=oid, path=path)
        if node is None:
            return
        for _ignored_curr_node, curr_path in self._walk(node):
            yield curr_path

    def listdir(self, *, oid: str = None, path: str = None):
        """
        returns a list of children of the node specified by oid, if oid is none then uses the node at path instead
        Args:
              oid: the target oid
              path the target path
        Returns:
              List[str]: the names of the target nodes children
        """
        node = self._get_node(oid=oid, path=path)
        if not node:
            return []
        return [x.name for x in node.children.values()]

    def mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None):
        """
        Creates a new directory node
        Args:
              path: the string path for the new node
              oid: the string oid for the new node
              metadata: the metadata dictinary for the new node
        """
        self._mkdir(path, oid, metadata)

    def _mkdir(self, path: str, oid: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> Node:
        new_node = self.__make_node(DIRECTORY, path, oid, metadata)
        return new_node

    def create(self, path: str, oid: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Creates a new file node
        Args:
              path: the string path for the new node
              oid: the string oid for the new node
              metadata: the metadata dictionary for the new node
        """
        self._create(path, oid, metadata)

    def _create(self, path: str, oid: str, metadata: Optional[Dict[str, Any]] = None) -> Node:
        return self.__make_node(FILE, path, oid, metadata=metadata)

    def delete(self, *, oid: str = None, path: str = None):
        """
        Removes the node specified by oid, if oid is none, removes the node ad path instead
        If target is a directory, recursively removes its children
        Args:
              oid: the path for the node to delete
              path: the path for the node to delete
        """
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
        if not remove_node or remove_node.is_root:
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

    def _split(self, path: str) -> Tuple[str, str]:
        parent, name = self._provider.split(path)
        while parent != path and not name:
            path = parent
            parent, name = self._provider.split(path)
        return parent, name

    def rename(self, old_path: str, new_path: str):
        """
        Changes a nodes path, deleting any node that may be in the new location
        Args:
              old_path: the path to the node to move
              new_path: the path to move the node to
        """
        self._rename(old_path, new_path)

    def _rename(self, old_path: str, new_path: str) -> Optional[Node]:
        node = self._get_node(path=old_path)
        if node and node.is_root:
            raise ValueError("cannot rename '%s'" % (old_path,))
        self._delete(node)  # _delete will delete the parent but not the children
        self.delete(path=new_path)  # renaming a nonexistent oid over an existing path should kick the target out of the tree
        if node:
            self.__insert_node(node, new_path)
            self._check(node)
        return node

    def _path_is_root(self, path: str) -> bool:
        parent_path, _ = self._provider.split(path)
        return parent_path == path

    def _unsafe_path_to_node(self, path: str) -> Node:
        # this method is "unsafe" because it depends on sanitizing the arguments
        if self._path_is_root(path):
            return self._root
        parent_path, name = self._split(path)
        parent_node = self._unsafe_path_to_node(parent_path)
        return parent_node.children.get(name) if parent_node else None

    def _get_node(self, *, oid: str = None, path: str = None) -> Node:
        if oid is not None:
            if oid == self._root.oid:
                return self._root
            return self._oid_to_node.get(oid)
        elif path is not None:
            norm_path = self._provider.normalize_path(path)
            if self._path_is_root(norm_path):
                return self._root
            return self._unsafe_path_to_node(norm_path)
        else:
            raise ValueError('get_node requires an oid or path')

    def set_oid(self, path: str, oid: str, otype: OType):
        """
        Sets the oid of the node at the target path, if the node is not found, makes a new node
        Args:
              path: the path to the node
              oid: the new oid for the node
              otype: the type of the target node
        """
        assert oid and path and otype
        node = self._get_node(path=path)
        if node:
            self._set_oid(node, oid)
        else:
            self.__make_node(otype, path, oid)

    def _set_oid(self, node: Node, oid):
        assert node is not None
        assert oid is not None
        if node.oid == oid:
            return
        self.delete(oid=oid)  # we know anything at that oid must be a different node
        if node.oid is None:
            node.oid = oid
            self._oid_to_node[oid] = node
        else:
            self.__make_node(node.type, node.full_path(), oid)


    def get_oid(self, path):
        """
        Gets the oid from the node at path
        Args:
              path: the path to retrieve the oid from
        Returns:
              str: oid from the target node
        """
        node = self._get_node(path=path)
        return node.oid if node else None

    def get_path(self, oid):
        """
        Gets the path from the node at oid
        Args:
              oid: the oid to retrieve a path from
        Returns:
              str: path from the target node
        """
        node = self._oid_to_node.get(oid)
        return node.full_path() if node else None

    def get_type(self, *, oid=None, path=None) -> Optional[OType]:
        """
        Gets the type from the node at oid, if oid is none gets the type from the node at path
        Args:
              oid: the target oid to get a type from
              path: the target path to get a type from
        Returns:
              OType: the type of the target node
        """
        node = self._get_node(oid=oid, path=path)
        return node.type if node else None

    def __iter__(self):
        return self.walk()
