import logging
import os
from typing import Dict
from cloudsync.tests.fixtures import Provider, mock_provider_instance

import pytest
log = logging.getLogger(__name__)

from cloudsync.hierarchical_cache import HierarchicalCache
# TODO: create tests for
#  case sensitive and case preserving
#  metadata preservation


def new_oid() -> str:
    return os.urandom(4).hex()


def new_cache(root_oid=None, root_metadata: Dict[str, any] = None):
    if not root_oid:
        root_oid = new_oid()
    provider = mock_provider_instance(oid_is_path=False, case_sensitive=True)  # todo: make this a fixture
    metadata_fields = set(root_metadata.keys()) if root_metadata else set()
    return HierarchicalCache(provider, root_oid, metadata_fields)


def test_walk():
    cache = new_cache()
    cache.create('/a', new_oid())
    cache.mkdir('/b', new_oid())
    cache.create('/b/c', new_oid())
    target = ['/', '/a', '/b', '/b/c']
    cache_walk = list(cache.walk())
    assert list(cache_walk) == target
    cache_walk = list(cache)
    assert list(cache_walk) == target


def test_create():
    cache = new_cache()
    a_oid = new_oid()
    cache.create('/a.txt', a_oid)

    a_file = cache.root.children['a.txt']
    assert(a_file.oid == a_oid)
    assert(a_file == cache._oid_to_node[a_oid])


def test_mkdir():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)

    a_folder = cache.root.children['a']
    assert(a_folder.oid == a_oid)
    assert(a_folder == cache._oid_to_node[a_oid])


def test_delete():
    cache = new_cache()
    # TODO: create and delete file

    # create and delete folder
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    cache.delete(a_oid)

    # TODO: create a file in the dir and make sure it's also gone when we delete the file's parent folder
    a = cache.get_oid('/a')
    assert(a is None)


def test_delete_on_nonexistent():
    cache = new_cache()
    node_found = cache.delete('nonexistent oid')
    assert not node_found


def test_delete_non_empty_folder():
    raise NotImplementedError()


def test_rename(): #check tree for new path, list shouldnt change once the nodes are re setup, parents and children shifted
    def check_results(cache: HierarchicalCache, oid, path, otype, has_children = None):
        assert cache.get_oid(path) == oid
        assert cache.get_path(oid) == path
        assert cache.get_type(oid=oid) == otype
        assert cache.get_type(path=path) == otype
        if has_children:
            assert cache._


    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    c_oid = new_oid()
    d_oid = new_oid()
    cache.create('/a', a_oid)
    cache.mkdir('/b', b_oid)
    cache.create('/b/c', c_oid)
    cache.mkdir('/d', d_oid)

    # test rename file
    cache.rename(a_oid, '/a1')
    assert cache.get_oid('/a1') == a_oid
    # test rename folder
    # test rename folder that contains a file and folder, confirm contents' paths have changed
    # test rename that only moves (file)
    # test rename that only moves (folder)
    # test rename that moves and renames (file)
    # test rename that moves and renames (folder)




    raise NotImplementedError()


def test_rename_non_existent_oid():
    raise NotImplementedError()


def test_rename_to_non_existent_path():
    raise NotImplementedError()


def test_rename_over_existent_path():
    raise NotImplementedError()


def test_reuse_oid():
    # TODO: test mkdir using a particular oid, then create a file with the same oid and different name
    #  this should delete the dir and its contents
    raise NotImplementedError


def test_make_hierarchy():
    root_oid = new_oid()
    cache = new_cache(root_oid=root_oid)
    a_oid = new_oid()
    b_oid = new_oid()
    c_oid = new_oid()
    d_oid = new_oid()

    cache.mkdir('/a', a_oid)
    cache.mkdir('/a/b/', b_oid)  # test stripping trailing separator
    cache.create('/a/b/c.txt', c_oid)
    cache.mkdir('/a/b/d', d_oid)

    a = cache.root.children['a']
    assert(a.oid == a_oid)
    b = a.children['b']
    log.error("b=%s", b)
    assert(b.oid == b_oid)
    c = b.children['c.txt']
    assert(c.oid == c_oid)
    d = b.children['d']
    assert(d.oid == d_oid)

    assert(a.parent.oid == root_oid)
    assert(b.parent.oid == a_oid)
    assert(c.parent.oid == b_oid)
    assert(d.parent.oid == b_oid)

    assert(a == cache._oid_to_node[a_oid])
    assert(b == cache._oid_to_node[b_oid])
    assert(c == cache._oid_to_node[c_oid])
    assert(d == cache._oid_to_node[d_oid])


def test_create_parent_is_a_file():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    cache.create('/a', a_oid)  # a is a FILE(!)
    cache.create('/a/b.txt', b_oid)
    # todo confirm that /a was replaced by a folder
    raise NotImplementedError()


def test_create_parent_doesnt_exist():
    cache = new_cache()
    b_oid = new_oid()
    cache.create('/a/b.txt', b_oid)
    # todo confirm that /a was created as a folder
    raise NotImplementedError()


def test_create_over_folder():
    # mkdir /a
    # create /a/b
    # confirm b is cached
    # create /a
    # confirm that a is file
    # confirm that b is no longer cached
    raise NotImplementedError()


def test_mkdir_parent_is_a_file():
    raise NotImplementedError()


def test_mkdir_parent_doesnt_exist():
    cache = new_cache()
    b_oid = new_oid()
    log.error("walk=%s", list(cache.walk()))
    cache.mkdir('/a/b', b_oid)
    # todo confirm that /a was created as a folder
    raise NotImplementedError()

def test_mkdir_over_file():
    # create /a
    # confirm that a is file
    # mkdir /a
    # confirm that a is a folder
    # create /a/b
    # confirm b is cached
    raise NotImplementedError()


def test_path_to_oid_success():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    a = cache.get_oid('/a')
    assert(a == a_oid)


def test_path_to_oid_failure():
    cache = new_cache()
    a = cache.get_oid('/a')
    assert(a is None)


def test_oid_to_path_success():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    a = cache.get_path(a_oid)
    assert(a == '/a')


def test_oid_to_path_failure():
    cache = new_cache()
    a = cache.get_oid('/nonexistent_path')
    assert(a is None)


