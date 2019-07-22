import time
import logging

from io import BytesIO

import pytest

from pycloud import SyncManager, SyncState, EventManager, CloudFileNotFoundError, LOCAL, REMOTE, FILE, DIRECTORY
from pycloud.runnable import time_helper

from .test_events import MockProvider

log = logging.getLogger(__name__)

@pytest.fixture(name="sync")
def fixture_sync():
    state = SyncState()

    def translate(to, path):
        if to == LOCAL:
            return "/local/" + path.replace("/remote/", "")

        if to == REMOTE:
            return "/remote/" + path.replace("/local/", "")

        raise ValueError()

    # two providers and a translation function that converts paths in one to paths in the other
    sync =  SyncManager(state, (MockProvider(), MockProvider()), translate)

    def run_until_found(*files, timeout=1):
        last_error = None

        def found():
             for side, path in files:
                try:
                    sync.providers[side].info_path(path)
                except CloudFileNotFoundError as e:
                    log.debug("waiting %s", e)
                    last_error = e
                    continue
                return True
      
        sync.run(timeout=timeout, until=found)

        if not found():
            raise last_error

    sync.run_until_found = run_until_found

    return sync


def test_sync_state_basic():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")

    assert state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="123")


def test_sync_state_rename():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")


def test_sync_state_multi():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")


def test_sync_basic(sync):
    local_path1 = sync.translate(LOCAL, "/remote/stuff")

    assert local_path1 == "/local/stuff"
    remote_path1 = "/remote/stuff"
    local_path2 = "/local/stuff2"
    remote_path2 = "/remote/stuff2"

    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.syncs.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.syncs.update(LOCAL, FILE, oid=linfo.oid, exists=True)

    assert sync.syncs.entry_count() == 1

    rinfo = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

    # inserts info about some cloud path
    sync.syncs.update(REMOTE, FILE, oid=rinfo.oid,
                      path=remote_path2, hash=rinfo.hash)

    def done():
        info = [None] * 4
        try:
            info[0] = sync.providers[LOCAL].info_path("/local/stuff")
            info[1] = sync.providers[LOCAL].info_path("/local/stuff2")
            info[2] = sync.providers[REMOTE].info_path("/remote/stuff")
            info[3] = sync.providers[REMOTE].info_path("/remote/stuff2")
        except CloudFileNotFoundError as e:
            log.debug("waiting for %s", e)
            pass

        return all(info)

    # loop the sync until the file is found
    sync.run(timeout=1, until=done)

    assert done()

    info = sync.providers[LOCAL].info_path("/local/stuff2")
    assert info.hash == sync.providers[LOCAL].hash_data(BytesIO(b"hello2"))
    assert info.oid
    log.debug("all syncs %s", sync.syncs.get_all())

def test_sync_rename(sync):
    local_path1 = "/local/stuff"
    local_path2 = "/local/stuff2"
    remote_path1 = "/remote/stuff"
    remote_path2 = "/remote/stuff2"

    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.syncs.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1), timeout=1)

    sync.syncs.update(LOCAL, FILE, path=local_path2,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path2), timeout=1)

    with pytest.raises(CloudFileNotFoundError):
        sync.providers[REMOTE].info_path("/remote/stuff")
