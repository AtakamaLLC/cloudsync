import pytest

from pycloud import EventManager

from . import util

class MockProvider:
    pass

@pytest.fixture
def manager()
    return EventManager(MockProvider)

def test_event_basic(util, manager):
    temp = util.temp_file(fill_bytes=32)
    cloud_id1, hash1 = provider.upload(temp, "/dest")

    # this is normally a blocking function that runs forever
    def done():
        return os.path.exists(local_path)

    # loop the sync until the file is found
    manager.run(timeout=1, until=done)

    local_path = manager.local_path("/fandango")

    util.fill_bytes(local_path, count=32)

    manager.local_event(path=local_path, exists=True)

    # loop the sync until the file is found
    manager.sync(timeout=1, until=done)

    info = provider.info("/fandango")

    assert info.hash == provider.local_hash(temp)
    assert info.cloud_id
