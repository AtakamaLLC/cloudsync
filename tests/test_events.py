import pytest
import os

from pycloud import EventManager
# from .util import util

from . import util

class MockProvider:
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
def manager(provider):
    return EventManager(provider)


def test_event_basic(util, manager):
    provider = MockProvider
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
