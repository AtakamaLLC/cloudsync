import pytest

from pycloud import SyncManager

@pytest.fixture
def sync():
    return SyncManager(EventManager(MockProvider))

def test_sync_basic(util, sync):
    full_path = sync.local_path("/local")

    # inserts info about some local path
    sync.update_local(path="/local", local_exists=True)

    # updates info about some local path, without duping
    sync.update_local(path="/local", local_exists=True)

    assert sync.entry_count() == 1

    # inserts info about some cloud path
    sync.update_cloud(path="/remote", cloud_id=12345, remote_exists=True, local_exists=False)

    # updates info about some cloud path... as if a name change occured
    sync.update_cloud(path="/remote2", cloud_id=12345, remote_exists=True, local_exists=False)

    def done():
        

    # loop the sync until the file is found
    sync.run(timeout=1, until=done)

    info = provider.info("/fandango")

    assert info.hash == provider.local_hash(temp)
    assert info.cloud_id
