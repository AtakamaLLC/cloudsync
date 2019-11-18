import logging
import os

import pytest

from cloudsync.hierarchical_cache import HierarchicalCache, DirNode


def get_cache():
    return HierarchicalCache(DirNode(0, '/'), '/')


def test_make_file():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_file('/a.txt', a_oid)

    a_file = cache.nodes_root.children['a.txt']
    assert(a_file.oid == a_oid)
    assert(a_file == cache.oid_to_nodes[a_oid])

def test_make_directory():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_directory('/a', a_oid)

    a_folder = cache.nodes_root.children['a']
    assert(a_folder.oid == a_oid)
    assert(a_folder == cache.oid_to_nodes[a_oid])


def test_make_hierarchy():
    cache = get_cache()
    a_oid = os.urandom(4)
    b_oid = os.urandom(4)
    c_oid = os.urandom(4)
    d_oid = os.urandom(4)

    cache.make_directory('/a', a_oid)
    cache.make_directory('/a/b/', b_oid)  # test stripping trailing separator
    cache.make_file('/a/b/c.txt', c_oid)
    cache.make_directory('/a/b/d', d_oid)

    a = cache.nodes_root.children['a']
    assert(a.oid == a_oid)
    b = a.children['b']
    assert(b.oid == b_oid)
    c = b.children['c.txt']
    assert(c.oid == c_oid)
    d = b.children['d']
    assert(d.oid == d_oid)

    assert(a.parents[0].oid == 0)
    assert(b.parents[0].oid == a_oid)
    assert(c.parents[0].oid == b_oid)
    assert(d.parents[0].oid == b_oid)

    assert(a == cache.oid_to_nodes[a_oid])
    assert(b == cache.oid_to_nodes[b_oid])
    assert(c == cache.oid_to_nodes[c_oid])
    assert(d == cache.oid_to_nodes[d_oid])


def test_cant_make_file_subdirectory_doesnt_exist():
    cache = get_cache()
    b_oid = os.urandom(4)
    with pytest.raises(KeyError):
        cache.make_file('/a/b.txt', b_oid)


def test_cant_make_directory_subdirectory_doesnt_exist():
    cache = get_cache()
    b_oid = os.urandom(4)
    with pytest.raises(KeyError):
        cache.make_directory('/a/b', b_oid)


def test_path_to_oid_success():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_directory('/a', a_oid)
    a = cache.path_to_oid('/a')
    assert(a == a_oid)


def test_path_to_oid_failure():
    cache = get_cache()
    a = cache.path_to_oid('/a')
    assert(a is None)


def test_oid_to_path_success():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_directory('/a', a_oid)
    a = cache.oid_to_path(a_oid)
    assert(a == '/a')


def test_oid_to_path_failure():
    cache = get_cache()
    a = cache.oid_to_path('1337')
    assert(a is None)


def test_remove():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_directory('/a', a_oid)
    cache.remove('/a')
    a = cache.path_to_oid('/a')
    assert(a is None)


def test_remove_on_nonexistent():
    pass


def test_remove_non_empty_folder():
    pass


def test_rename(): #check tree for new path, list shouldnt change once the nodes are re setup, parents and children shifted
    pass


def test_rename_non_existent_oid():
    pass


def test_rename_to_non_existent_path():
    pass


def test_rename_over_existent_path():
    pass


