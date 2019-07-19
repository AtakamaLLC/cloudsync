from io import BytesIO

import pytest

from pycloud import SyncManager, SyncState, EventManager, LOCAL, REMOTE, FILE, DIRECTORY

from .test_events import MockProvider


@pytest.fixture
def sync():
    state = SyncState()

    def translate(to, path):
        if to == LOCAL:
            return "/local/" + path.replace("/remote/","")

        if to == REMOTE:
            return "/remote/" + path.replace("/local/","")

    # two providers and a translation function that converts paths in one to paths in the other
    return SyncManager(state, (MockProvider(), MockProvider()), translate)

def test_sync_state():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="foo", hash=b"foo")

    assert state.lookup_path(LOCAL, path="foo")

def test_sync_basic(sync):
    local_path1 = sync.translate(LOCAL, "/remote/stuff")

    assert local_path1 == "/local/stuff"
    remote_path1 = "/remote/stuff"
    local_path2 = "/local/stuff2"
    remote_pat21 = "/remote/stuff2"

    info = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, path=local_path1, oid=info.oid, hash=linfo.hash)

    # updates info about some local path, without duping
    sync.state.update(LOCAL, path=local_path1, exists=True)

    sync.state.update(LOCAL, oid=info.oid, exists=True)

    assert sync.state.entry_count() == 1

    rinfo = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello"))

    # inserts info about some cloud path
    sync.state.update(REMOTE, oid=rinfo.oid, path=remote_path2, hash=rinfo.hash)

    def done():
        info = list(range(4))

        info[0] = sync.providers[LOCAL].info_path("/local/stuff")
        info[1] = sync.providers[LOCAL].info_path("/local/sutff2")
        info[2] = sync.providers[LOCAL].info_path("/remote/stuff")
        info[3] = sync.providers[LOCAL].info_path("/remote/sutff2")

        return all(info)
         

    # loop the sync until the file is found
    sync.run(timeout=1, until=done)

    info = sync.providers[LOCAL].info_path("/local/stuff2")
    assert info.hash == provider.hash_data(b"hello2")
    assert info.oid
    assert info.oid == sync.syncs.get(LOCAL, oid=info.oid).s
