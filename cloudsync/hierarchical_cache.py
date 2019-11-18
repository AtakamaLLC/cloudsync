import logging


class Node:
    def __init__(self, oid, name):
        self.oid = oid
        self.parents = []
        self.name = name

    def add_parent(self, parent_node, name):
        self.parents[name] = parent_node


class DirNode(Node):
    def __init__(self, *args):
        super().__init__(*args)
        self.children = {}

    def add_child(self, child_node):
        self.children += [child_node]


class FileNode(Node):
    def __init__(self, *args):
        super().__init__(*args)


class HierarchicalCache:
    def __init__(self, root: DirNode, separator: str):
        self.nodes_root = root
        self.sep = separator
        self.oid_to_nodes = {root.oid: root}

    def __make_node(self, new_path, new_oid, node):
        parent_path, node_name = new_path.rsplit(self.sep, 1)
        if parent_path == '':
            parent_path = '/'

        parent_node = self.get_node_by_path(parent_path)
        if parent_node is None:
            raise KeyError('Parent must be added before child can be added')

        new_node = node(new_oid, node_name)
        parent_node.children[node_name] = new_node
        new_node.parents += [parent_node]
        self.oid_to_nodes[new_oid] = new_node
        return new_node

    def make_directory(self, new_path, new_oid, *args):
        new_node = self.__make_node(new_path.rstrip(self.sep), new_oid, *args, DirNode)
        self.oid_to_nodes[new_oid] = new_node

    def make_file(self, *args):
        self.__make_node(*args, FileNode)

    def remove(self, path_to_remove):
        parent_path, remove_node_name = path_to_remove.rsplit(self.sep, 1)
        if parent_path == '':
            parent_path = '/'
        parent_node = self.get_node_by_path(parent_path)
        node_to_remove = self.get_node_by_path(path_to_remove)
        if not (parent_node and node_to_remove):
            return False
        parent_node.children.pop(remove_node_name)
        self.oid_to_nodes.pop(node_to_remove.oid)

    def rename(self, oid, new_path):
        raise NotImplementedError

    def get_node_by_path(self, path_to_object):
        def _path_to_oid(_path_to_object, node):
            if self.sep not in _path_to_object:
                return node.children.get(_path_to_object)
            next_node_name, next_path = _path_to_object.split(self.sep, 1)
            logging.error(f'Path is {_path_to_object}, next node name is {next_node_name}, next path is {next_path}')
            next_node = node.children.get(next_node_name)
            if next_node is None:
                return None
            return _path_to_oid(next_path, next_node)
        if len(path_to_object) > 0 and path_to_object[0] == self.sep:
            path_to_object = path_to_object[1:]
        else:
            raise ValueError('Bad path?')
        if path_to_object is '':
            return self.nodes_root
        return _path_to_oid(path_to_object, self.nodes_root)

    def path_to_oid(self, path):
        node = self.get_node_by_path(path)
        return node.oid if node else None

    def oid_to_path(self, oid):
        node = self.oid_to_nodes.get(oid)
        if not node:
            return None

        def backtrace_path(current_node):
            if current_node.oid == self.nodes_root.oid:
                return ''
            return backtrace_path(current_node.parents[0]) + self.sep + current_node.name
        return backtrace_path(node)


    def __iter__(self):
        pass
