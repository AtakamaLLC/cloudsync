import pytest
import os

from pycloud import EventManager

class MockProvider:
    def __init__(self):
        self._fs = {}

    def upload(self, local_file, remote_file) -> list:
        pass

    def download(self, local_file, remote_file) -> list:
        pass

    def exists(self, remote_file) -> bool:
        pass

    def local_hash(self, local_file):
        pass

    def hash(self, remote_file):
        pass

    def events(self):
        pass


@pytest.fixture
def manager():
    return EventManager(MockProvider())  # TODO extend this to take any provider

def test_event_basic(util, manager):
    provider = manager.provider
    temp = util.temp_file(fill_bytes=32)
    info = provider.upload(temp, "/dest")

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
