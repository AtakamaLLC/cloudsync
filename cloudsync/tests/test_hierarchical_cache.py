import logging
import os
import weakref
from typing import Dict, Optional, Type, List, Any
from cloudsync.tests.fixtures import Provider, mock_provider_instance
from cloudsync import FILE, DIRECTORY
import gc

import pytest
log = logging.getLogger(__name__)

from cloudsync.hierarchical_cache import HierarchicalCache, Node
# TODO: create tests for
#  case sensitive and case preserving
#  metadata preservation


def new_oid() -> str:
    return os.urandom(4).hex()


def new_cache(root_oid=None, root_metadata: Dict[str, Any] = None, metadata_template: Optional[Dict[str, Type]]=None):
    if root_oid is None:
        root_oid = new_oid()
    provider = mock_provider_instance(oid_is_path=False, case_sensitive=True)  # todo: make this a fixture
    return HierarchicalCache(provider, root_oid, metadata_template, root_metadata)


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
    check_structure(cache)


def test_create():
    cache = new_cache()
    a_oid = new_oid()
    cache.create('/a.txt', a_oid)

    a_file = cache._root.children['a.txt']
    assert(a_file.oid == a_oid)
    assert(a_file == cache._oid_to_node[a_oid])
    check_structure(cache)


def test_mkdir():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)

    a_folder = cache._root.children['a']
    assert(a_folder.oid == a_oid)
    assert(a_folder == cache._oid_to_node[a_oid])
    check_structure(cache)


def test_delete():
    cache = new_cache()
    # TODO: create and delete file

    # create and delete folder
    a_oid = new_oid()
    cache.create('/b', new_oid())
    cache.mkdir('/a', a_oid)
    a_node = cache._root.children['a']
    b_node = cache._root.children['b']
    cache.delete(oid=a_oid)
    assert a_node not in cache._oid_to_node.values()
    assert a_node not in cache._root.children.values()
    assert b_node in cache._oid_to_node.values()
    assert b_node in cache._root.children.values()
    check_structure(cache)


    # TODO: create a file in the dir and make sure it's also gone when we delete the file's parent folder
    a = cache.get_oid('/a')
    assert(a is None)
    check_structure(cache)


def test_delete_on_nonexistent():
    cache = new_cache()
    node_found = cache.delete(oid='nonexistent oid')
    assert not node_found
    check_structure(cache)


def test_delete_non_empty_folder():
    cache = new_cache()

    # create and delete non-empty folder
    a_oid = new_oid()
    b_oid = new_oid()
    cache.mkdir('/a', a_oid)
    cache.create('/a/b', b_oid)

    walk = ['/', '/a', '/a/b']
    check_walk(cache, walk)

    cache.delete(oid=a_oid)
    # TODO: create a file in the dir and make sure it's also gone when we delete the file's parent folder
    assert cache.get_oid('/a') is None
    assert cache.get_oid('/a/b') is None
    assert cache.get_oid('/a') is None  # double check after '/a/b' didn't autocreate '/a' or something stupid

    walk = ['/']
    check_walk(cache, walk)


def check_walk(cache: HierarchicalCache, walk):
    assert sorted(list(cache)) == sorted(walk)


def check_results(cache: HierarchicalCache, oid, path, otype, child_names=None, child_oids=None, walk=None):
    assert cache.get_oid(path) == oid
    assert cache.get_type(path=path) == otype
    if oid is not None:
        assert cache.get_path(oid) == path
        assert cache.get_type(oid=oid) == otype
    if child_names:
        assert sorted(cache.listdir(oid=oid, path=path)) == sorted(child_names)
    if child_oids:
        found_oids = [x.oid for x in cache._get_node(oid=oid, path=path).children.values()]
        assert sorted(found_oids) == sorted(child_oids)
    check_structure(cache)


def test_rename(): #check tree for new path, list shouldnt change once the nodes are re setup, parents and children shifted
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    c_oid = new_oid()
    c1_oid = new_oid()
    d_oid = new_oid()
    cache.create('/a', a_oid)
    cache.mkdir('/b', b_oid)
    cache.create('/b/c', c_oid)
    cache.mkdir('/b/c1', c1_oid)
    cache.mkdir('/d', d_oid)

    walk = ['/', '/a', '/b', '/b/c', '/b/c1', '/d']
    check_walk(cache, walk)

    # test rename file
    cache.rename('/a', '/a1')
    check_results(cache, a_oid, '/a1', FILE)
    walk = ['/', '/a1', '/b', '/b/c', '/b/c1', '/d']
    check_walk(cache, walk)

    # test rename folder
    cache.rename('/d', '/d1')
    check_results(cache, d_oid, '/d1', DIRECTORY, child_names=[])
    walk = ['/', '/a1', '/b', '/b/c', '/b/c1', '/d1']
    check_walk(cache, walk)

    # test rename folder that contains a file and folder, confirm contents' paths have changed
    cache.rename('/b', '/b1')
    check_results(cache, b_oid, '/b1', DIRECTORY, ['c', 'c1'], [c_oid, c1_oid])
    check_results(cache, c_oid, '/b1/c', FILE)
    check_results(cache, c1_oid, '/b1/c1', DIRECTORY, child_names=[])
    walk = ['/', '/a1', '/b1', '/b1/c', '/b1/c1', '/d1']
    check_walk(cache, walk)

    # test rename that only moves (file)
    cache.rename('/a1', '/b1/a1')
    check_results(cache, a_oid, '/b1/a1', FILE)
    check_results(cache, b_oid, '/b1', DIRECTORY, ['a1', 'c', 'c1'], [a_oid, c_oid, c1_oid])
    walk = ['/', '/b1/a1', '/b1', '/b1/c', '/b1/c1', '/d1']
    check_walk(cache, walk)

    # test rename that only moves (folder)
    cache.rename('/b1', '/d1/b1')
    check_results(cache, b_oid, '/d1/b1', DIRECTORY, ['a1', 'c', 'c1'], [a_oid, c_oid, c1_oid])
    check_results(cache, c_oid, '/d1/b1/c', FILE)
    check_results(cache, c1_oid, '/d1/b1/c1', DIRECTORY, child_names=[])
    walk = ['/', '/d1/b1/a1', '/d1/b1', '/d1/b1/c', '/d1/b1/c1', '/d1']
    check_walk(cache, walk)

    # test rename that moves and renames (file)
    cache.rename('/d1/b1/a1', '/a')
    check_results(cache, a_oid, '/a', FILE)
    check_results(cache, b_oid, '/d1/b1', DIRECTORY, ['c', 'c1'], [c_oid, c1_oid])
    walk = ['/', '/a', '/d1/b1', '/d1/b1/c', '/d1/b1/c1', '/d1']
    check_walk(cache, walk)

    # test rename that moves and renames (folder)
    cache.rename('d1/b1', '/b')
    check_results(cache, b_oid, '/b', DIRECTORY, ['c', 'c1'], [c_oid, c1_oid])
    check_results(cache, d_oid, '/d1', DIRECTORY, [], [])
    walk = ['/', '/a', '/b', '/b/c', '/b/c1', '/d1']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_non_existent_oid():
    cache = new_cache(new_oid())
    cache.mkdir('/a/b', new_oid())
    cache.create('/a/b/c', new_oid())
    walk = ['/', '/a', '/a/b', '/a/b/c']
    check_walk(cache, walk)

    # make sure this doesn't raise an exception, or change the tree in any way
    cache.rename('/junk', '/junk2')
    walk = ['/', '/a', '/a/b', '/a/b/c']
    check_walk(cache, walk)

    # renaming non-existent oid over existing path should kick the existent path out of the tree
    cache.rename('/junk', '/a/b/c')
    walk = ['/', '/a', '/a/b']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_to_non_existent_path():
    cache = new_cache(new_oid())
    a_oid = new_oid()
    cache.create('/a', a_oid)
    walk = ['/', '/a']
    check_walk(cache, walk)

    cache.rename('/a', '/junk/a')
    check_results(cache, a_oid, '/junk/a', FILE)

    walk = ['/', '/junk', '/junk/a']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_file_over_file():
    cache = new_cache(new_oid())

    oid_1a = new_oid()
    cache.create('/f1a', oid_1a)
    oid_1b = new_oid()
    cache.create('/f1b', oid_1b)

    walk = ['/', '/f1a', '/f1b']
    check_walk(cache, walk)

    cache.rename('/f1a', '/f1b')
    check_results(cache, oid_1a, '/f1b', FILE)

    walk = ['/', '/f1b']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_file_over_folder():
    cache = new_cache(new_oid())
    oid_2a = new_oid()
    cache.create('/f2a', oid_2a)
    oid_2b = new_oid()
    cache.mkdir('/d2b', oid_2b)
    cache.create('/d2b/d2b_file', new_oid())

    walk = ['/', '/f2a', '/d2b', '/d2b/d2b_file']
    check_walk(cache, walk)

    # Rename a file over a folder
    cache.rename('/f2a', '/d2b')
    check_results(cache, oid_2a, '/d2b', FILE)
    walk = ['/', '/d2b']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_folder_over_folder():
    cache = new_cache(new_oid())
    oid_3a = new_oid()
    cache.mkdir('/d3a', oid_3a)
    cache.create('/d3a/d3a_file', new_oid())
    oid_3b = new_oid()
    cache.mkdir('/d3b', oid_3b)
    cache.create('/d3b/d3b_file', new_oid())

    walk = ['/', '/d3a', '/d3a/d3a_file', '/d3b', '/d3b/d3b_file']
    check_walk(cache, walk)

    # Rename a folder over a folder
    cache.rename('/d3a', '/d3b')
    check_results(cache, oid_3a, '/d3b', DIRECTORY)
    walk = ['/', '/d3b', '/d3b/d3a_file']
    check_walk(cache, walk)
    check_structure(cache)


def test_rename_folder_over_file():
    cache = new_cache(new_oid())
    oid_4a = new_oid()
    cache.mkdir('/d4a', oid_4a)
    cache.create('/d4a/d4a_file', new_oid())
    oid_4b = new_oid()
    cache.create('/f4b', oid_4b)

    walk = ['/', '/d4a', '/d4a/d4a_file', '/f4b']
    check_walk(cache, walk)

    # Rename a folder over a file
    cache.rename('/d4a', '/f4b')
    check_results(cache, oid_4a, '/f4b', DIRECTORY)

    walk = ['/', '/f4b', '/f4b/d4a_file']
    check_walk(cache, walk)
    check_structure(cache)


def test_reuse_oid():
    # test mkdir using a particular oid, then create a file with the same oid and different name
    #  this should delete the dir and its contents
    cache = new_cache(new_oid())
    oid = new_oid()
    cache.mkdir('/a', oid)
    cache.create('/a/b', new_oid())
    walk = ['/', '/a', '/a/b']
    check_walk(cache, walk)
    check_results(cache, oid, '/a', DIRECTORY)

    cache.create('/c', oid)
    walk = ['/', '/c']
    check_walk(cache, walk)
    check_results(cache, oid, '/c', FILE)
    assert cache.get_oid('/a') is None
    check_structure(cache)


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

    a = cache._root.children['a']
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
    check_structure(cache)


def test_create_parent_is_a_file():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    cache.create('/a', a_oid)  # a is a FILE(!)
    assert cache.get_type(path='/a') == FILE
    cache.create('/a/b.txt', b_oid)
    # todo confirm that '/a' was replaced by a folder and the old oid is gone
    assert cache.get_path(a_oid) is None
    assert cache.get_type(path='/a') == DIRECTORY
    a_new_oid = cache.get_oid('/a')
    assert a_new_oid != a_oid
    assert a_new_oid is None
    check_structure(cache)


def test_create_parent_doesnt_exist():
    cache = new_cache()
    b_oid = new_oid()
    cache.create('/a/b', b_oid)
    # confirm that /a was created as a folder
    check_results(cache, None, '/a', DIRECTORY, ['b'], [b_oid])
    check_structure(cache)


def confirm_gone(cache, oid=None, path=None):
    if oid is not None:
        assert cache.get_path(oid) is None
    assert cache.get_oid(path) is None


def test_create_over_folder():
    cache = new_cache()
    # mkdir /a
    a1_oid = new_oid()
    cache.mkdir('/a', a1_oid)
    # create /a/b
    b_oid = new_oid()
    cache.create('/a/b', b_oid)
    # confirm b is cached
    check_results(cache, b_oid, '/a/b', FILE)
    # create /a
    a2_oid = new_oid()
    cache.create('/a', a2_oid)
    # confirm that a is file
    check_results(cache, a2_oid, '/a', FILE)
    # confirm that the contents of the folder that disappeared are also gone
    confirm_gone(cache, b_oid, '/a/b')
    check_structure(cache)


def test_mkdir_parent_is_a_file():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    cache.create('/a', a_oid)  # a is a FILE(!)
    assert cache.get_type(path='/a') == FILE
    cache.mkdir('/a/b', b_oid)
    # confirm that '/a' was replaced by a folder and the old oid is gone
    assert cache.get_path(a_oid) is None
    assert cache.get_type(path='/a') == DIRECTORY
    a_new_oid = cache.get_oid('/a')
    assert a_new_oid != a_oid
    assert a_new_oid is None
    check_structure(cache)


def test_mkdir_parent_doesnt_exist():
    cache = new_cache()
    b_oid = new_oid()
    cache.mkdir('/a/b', b_oid)
    # confirm that /a was created as a folder
    check_results(cache, None, '/a', DIRECTORY, ['b'], [b_oid])
    check_structure(cache)


def test_mkdir_over_file():
    cache = new_cache()
    # create /a
    cache.create('/a', new_oid())
    # confirm that a is file
    assert cache.get_type(path='/a') == FILE
    # mkdir /a
    cache.mkdir('/a', new_oid())
    # confirm that a is a folder
    assert cache.get_type(path='/a') == DIRECTORY
    # create /a/b
    cache.create('/a/b', new_oid())
    # confirm b is cached
    assert cache.get_type(path='/a/b') == FILE
    check_structure(cache)


def test_path_to_oid_success():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    a = cache.get_oid('/a')
    assert(a == a_oid)
    check_structure(cache)


def test_path_to_oid_failure():
    cache = new_cache()
    a = cache.get_oid('/a')
    assert(a is None)
    check_structure(cache)


def test_oid_to_path_success():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    a = cache.get_path(a_oid)
    assert(a == '/a')
    check_structure(cache)


def test_oid_to_path_failure():
    cache = new_cache()
    a = cache.get_oid('/nonexistent_path')
    assert(a is None)
    check_structure(cache)


def test_delete_folder_without_oid():
    root_oid = 'root-oid'
    cache = new_cache(root_oid)
    b_oid = new_oid()
    cache.create('/a/b',  b_oid)
    print("b oid is %s", b_oid)
    log.debug("cache oids = %s", cache._oid_to_node.keys())
    assert len(cache._oid_to_node) == 2 # root oid and b
    assert cache.get_type(path='/a') == DIRECTORY
    cache.delete(path='/a')
    assert len(cache._oid_to_node) == 1
    assert list(cache._oid_to_node.keys())[0] == root_oid
    check_structure(cache)


def test_rename_folder_without_oid():
    root_oid = 'root-oid'
    cache = new_cache(root_oid)
    b_oid = new_oid()
    cache.create('/a/b',  b_oid)
    print("b oid is %s", b_oid)
    log.debug("cache oids = %s", cache._oid_to_node.keys())
    assert len(cache._oid_to_node) == 2  # root oid and b
    assert cache.get_type(path='/a') == DIRECTORY
    cache.rename('/a', '/c')
    assert cache.get_type(path='/c/b') == FILE
    assert len(cache._oid_to_node) == 2  # rename doesn't change that, still 2
    assert list(cache._oid_to_node.keys())[0] == root_oid
    check_structure(cache)


def test_create_node_over_existing_path_and_oid():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    cache.create('/a', a_oid)
    cache.create('/b', b_oid)
    assert cache.get_type(path='/a') == FILE
    assert cache.get_type(oid=a_oid) == FILE
    assert cache.get_type(path='/b') == FILE
    assert cache.get_type(oid=b_oid) == FILE

    cache.mkdir('/b', a_oid)
    assert cache.get_type(path='/a') is None
    assert cache.get_type(path='/b') == DIRECTORY
    assert cache.get_type(oid=b_oid) is None
    assert cache.get_type(oid=a_oid) == DIRECTORY
    check_structure(cache)


def test_update():
    cache = new_cache(root_metadata={'throws': 'pork products'}, metadata_template={'throws': str, 'speed': str})
    a_oid = new_oid()
    a2_oid = new_oid()
    cache.mkdir('/a', a_oid)

    cache.update('/a', DIRECTORY)
    assert(cache.get_oid('/a') is a_oid)
    assert(cache.get_type(path='/a') is DIRECTORY)

    cache.update('/a', FILE, a2_oid)
    assert(cache.get_oid('/a') is a2_oid)
    assert(cache.get_type(path='/a') is FILE)

    cache.update('/a', FILE, a_oid)
    assert(cache.get_oid('/a') is a_oid)

    cache.update('/a', FILE, metadata={'throws': 'dak ham'}, keep=True)
    assert(len(cache.get_metadata(path='/a')) == 1)
    assert(cache.get_metadata(path='/a')['throws'] == 'dak ham')

    cache.update('/a', FILE, metadata={'speed': 'mach 4'}, keep=True)
    assert(len(cache.get_metadata(path='/a')) == 2)
    assert(cache.get_metadata(path='/a')['speed'] == 'mach 4')

    cache.update('/a', FILE, metadata={'throws': 'spam'}, keep=False)
    assert(len(cache.get_metadata(path='/a')) == 1)
    assert(cache.get_metadata(path='/a')['throws'] == 'spam')


def test_metadata():
    cache = new_cache(
        metadata_template={'ph level': str},
        root_metadata={'ph level': '1'}
    )
    assert(cache.get_metadata(path='/a') is None)
    assert(cache.get_metadata(path='/')['ph level'] == '1')
    assert(len(cache.get_metadata(path='/')) == 1)

    cache.set_metadata({'ph level': '7'}, path='/a')
    assert(cache.get_metadata(path='/a') is None)
    assert(len(cache.get_metadata(path='/')) == 1)

    cache.set_metadata({'ph level': 'pumpkin spice'}, path='/')
    assert(cache.get_metadata(path='/')['ph level'] == 'pumpkin spice')
    assert(len(cache.get_metadata(path='/')) == 1)

    try:
        cache.set_metadata({'fake data': 'catapults are the perfect seige equipment'}, path='/')
        assert False
    except ValueError:
        pass
    try:
        cache.set_metadata({'ph level': 11}, path='/')
        assert False
    except ValueError:
        pass


#bad still
def test_walk_returns_nothing_for_bad_node():
    cache = new_cache()
    walked = 0
    for _ in cache.walk(path='/totally existent path'):
        walked += 1
    assert(walked == 0)


def test_listdir_returns_empty_for_bad_node():
    cache = new_cache()
    assert(cache.listdir(path='/totally existent path') == [])
    cache.mkdir('/a', new_oid())

def test_cant_rename_root():
    cache = new_cache()
    try:
        cache.rename('/', 'thanks path very cool')
        assert False
    except ValueError:
        pass


def test_delete_malformed_nodes():
    cache = new_cache()
    a_oid = new_oid()
    cache.mkdir('/a', a_oid)
    cache._root.children = {}
    cache.delete(oid=a_oid)

    b_oid = new_oid()
    c_oid = new_oid()
    tmp_oid = new_oid()
    cache.mkdir('/b', b_oid)
    cache.mkdir('/c', c_oid)
    cache.mkdir('/c/tmp', tmp_oid)
    cache._root.children['b'] = cache._root.children['c']
    try:
        cache.delete(oid=b_oid)
        assert False
    except LookupError:
        pass


def test_get_root_node():
    cache = new_cache(root_oid='0')
    assert(cache.get_type(oid='0') is not None)


def test_get_node_needs_oid_or_path():
    cache = new_cache()
    try:
        cache.get_type()
        assert False
    except ValueError:
        pass


def test_set_oid():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    c_oid = new_oid()

    failed = False
    try:
        cache.set_oid(None, a_oid, DIRECTORY)
        failed = True
    except AssertionError:
        pass
    assert not failed

    try:
        cache.set_oid('/a', None, DIRECTORY)
        failed = True
    except AssertionError:
        pass
    assert not failed

    try:
        cache.set_oid('/a', a_oid, None)
        failed = True
    except AssertionError:
        pass
    assert not failed

    cache.set_oid('/a', a_oid, DIRECTORY)
    assert(cache.get_oid('/a') == a_oid)

    cache.mkdir('/b', None)
    cache.set_oid('/b', b_oid, DIRECTORY)
    assert(cache.get_oid('/b') == b_oid)

    node = cache._get_node(oid=b_oid)
    cache._set_oid(node, b_oid)
    assert(cache.get_oid('/b') == b_oid)

    cache.set_oid('/b', c_oid, DIRECTORY)
    assert(cache.get_oid('/b') == c_oid)
    assert(len(cache.listdir(path='/')) == 2)

    try:
        cache.set_oid('/b', None, DIRECTORY)
        failed = True
    except AssertionError:
        pass
    assert not failed


def test_node_check_asserts_for_parent_oids():
    provider = mock_provider_instance(oid_is_path=False, case_sensitive=True)
    parent_node = Node(provider, DIRECTORY, '0', '', None, None)
    child_node = Node(provider, DIRECTORY, '0', 'a', parent_node, None)

    fail = False
    child_node.wr_parent = weakref.ref(child_node)
    try:
        child_node.check()
        fail = True
    except AssertionError:
        pass
    assert not fail

    child_node.wr_parent = weakref.ref(parent_node)
    try:
        child_node.check()
        fail = True
    except AssertionError:
        pass
    assert not fail


def test_node_set_oid():
    provider = mock_provider_instance(oid_is_path=False, case_sensitive=True)
    test_node = Node(provider, DIRECTORY, None, '', None, None)

    test_node.oid = '0'
    assert(test_node.oid == '0')

    test_node.oid = '1'
    assert(test_node.oid == '1')

    try:
        test_node.oid = None
        assert False
    except AssertionError:
        pass

    test_node.oid = 0


def test_split_path():
    cache = new_cache()
    a_oid = new_oid()
    b_oid = new_oid()
    cache.mkdir('/a', a_oid)
    cache.mkdir('/b', b_oid)

    parent, name = cache._split('/a/b///')
    assert(parent == '/a')
    assert(name == 'b')


def test_add_child():
    provider = mock_provider_instance(oid_is_path=False, case_sensitive=True)
    parent_node = Node(provider, DIRECTORY, '0', '', None, None)
    child_node = Node(provider, DIRECTORY, '0', 'a', None, None)

    parent_node.add_child(child_node)
    assert(len(parent_node.children) == 1)
    assert(parent_node.children['a'] == child_node)


def full_split(provider: Provider, path: str):
    retval: List[str] = []
    while path not in ('', '/'):
        parent, base = provider.split(path)
        retval.insert(0, base)
        path = parent
    return retval


def check_structure(cache: HierarchicalCache):
    #   todo: confirm that the internal structure of the cache is good
    #       check every node in the tree
    #           is in the oid_to_node dict if it has an oid,
    #           has an oid_to_node entry that points to the correct node
    #           has an entry in it's parent's children dict under the correct name
    #       check every node in oid_to_node
    #           traverse the tree starting at the root all the way to the node
    node: Node
    for node, path in cache._walk(cache._root, '/'):
        if node.oid:
            assert cache._oid_to_node[node.oid] is node
        if node is not cache._root:
            parent_node = node.parent
            assert node.parent
            assert parent_node.children[node.name] is node
            full_path = node.full_path()
            if path != full_path:
                assert path == full_path  # compare walking the parents with walking the children

    for oid, node in cache._oid_to_node.items():
        assert node.oid == oid
        path = cache.get_path(node.oid)

        # this reiterates the same check above for everything that's in the tree,
        # but we retest anyway because this will help expose if any node is in oid_to_node
        # but not also in the tree
        parts = full_split(cache._provider, path)
        log.debug("%s %s", path, parts)
        currnode = cache._root
        for part in parts[0:-1]:
            assert part in currnode.children
            currnode = currnode.children[part]
            assert currnode.type == DIRECTORY
        if node is not cache._root:
            last_part = parts[-1]
            currnode = currnode.children[last_part]
            assert currnode.oid == oid  # check the key in oid_to_node
            assert currnode is node  # checks that all the parents
