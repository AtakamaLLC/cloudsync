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

    assert(cache.nodes_root.children['a.txt'].oid == a_oid)


def test_make_directory():
    cache = get_cache()
    a_oid = os.urandom(4)
    cache.make_directory('/a', a_oid)

    assert(cache.nodes_root.children['a'].oid == a_oid)


def test_make_hierarchy():
    cache = get_cache()
    a_oid = os.urandom(4)
    b_oid = os.urandom(4)
    c_oid = os.urandom(4)

    cache.make_directory('/a', a_oid)
    cache.make_directory('/a/b/', b_oid)  # test stripping trailing separator
    cache.make_file('/a/b/c.txt', c_oid)

    a = cache.nodes_root.children['a']
    assert(a.oid == a_oid)
    logging.error(f'a is {a}')
    logging.error(f'a has children {a.children}')
    logging.error(f"b is {a.children['b']}")
    b = a.children['b']
    assert(b.oid == b_oid)

    c = b.children['c.txt']
    assert(c.oid == c_oid)

    assert(a.parents['/'].oid == 0)
    assert(b.parents['a'].oid == a_oid)
    assert(c.parents['b'].oid == b_oid)


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


def test_oid_to_path_failure():
    cache = get_cache()
    a = cache.path_to_oid('/a')
    assert(a is None)
