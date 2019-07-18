import pytest

from pycloud import SyncManager, SyncState

from . import util
 
@pytest.fixture
def sync():
    state = SyncState()
    return SyncManager(state, EventManager(state, MockProvider()))

def test_sync_basic(util, sync):
    full_path = sync.remote_to_local("/stuff")

    # inserts info about some local path
    sync.state.update(local_path=full_path, exists=True)

    # updates info about some local path, without duping
    sync.state.update(local_path=full_path, exists=True)

    # updates info about some local path, without duping
    sync.state.rename(local_path=full_path, new_path=sync.remote_to_local("/stuff2"))

    assert sync.state.entry_count() == 1

    # inserts info about some cloud path
    sync.state.update(remote_id=12345, remote_path="/fandango", exists=True)

    # updates info about some cloud path... as if a name change occured
    sync.state.update(remote_id=12345, remote_path="/fandango2")

    def done():
        info1 = provider.info("/fandango2")
        info2 = provider.info("/stuff2")
        local1 = sync.remote_to_local("/stuff2")
        local2 = sync.remote_to_local("/fandango2")

        return info1 is not None and info2 is not None and os.path.exists(local1) and os.path.exists(local2)
         

    # loop the sync until the file is found
    sync.run(timeout=1, until=done)

    info = provider.info("/fandango")

    assert info.hash == provider.local_hash(temp)
    assert info.cloud_id
