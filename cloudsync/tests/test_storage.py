import os
from typing import Dict

import pytest

from cloudsync import SqliteStorage
from cloudsync.utils import NamedTemporaryFile

from .fixtures import MockStorage

@pytest.fixture(name="sqlite_store")
def fixture_sqlite_storage():
    f = NamedTemporaryFile(mode=None)
    s = SqliteStorage(f.name)
    yield s 
    s.close()
    del f

@pytest.fixture(name="mock_store")
def fixture_mock_storage():
    d: Dict[str, Dict[int, bytes]] = {}
    s = MockStorage(d)
    yield s 
    s.close()

@pytest.fixture(name="store", params=[0, 1], ids=["mock","sqlite"])
def fixture_storage(request, mock_store, sqlite_store):
    stores = (mock_store, sqlite_store)
    yield stores[request.param]

def test_storage_update(store):
    eid = store.create("tag", b'bar')
    store.update("tag", b'baz', eid)
    store.delete("tag", eid)
    store.delete("tag", eid)
    assert store.read_all("tag") == {}

def test_storage_read_multi(store):
    id1 = store.create("tag1", b'bar')
    id2 = store.create("tag2", b'baz')
    rall = store.read_all() 
    assert rall == {"tag1":{id1:b'bar'}, "tag2":{id2:b'baz'}}


def test_storage_close(store):
    store.close()
    if isinstance(store, SqliteStorage):
        # this only works on windows if the file is closed
        os.unlink(store._filename)
    # ok to close twice
    store.close()
