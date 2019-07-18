import pytest
import os
from hashlib import md5

from pycloud import EventManager, CloudFileNotFoundError
from . import util


class MockProvider:
    class File:
        def __init__(self, name, contents=b""):
            # self.display_name = name  # TODO: used for case insensitive file systems
            self.name = name
            self.contents = contents
            self.id = id(self)

        def hash(self):
            return md5(self.contents).hexdigest()

    def __init__(self, case_insensitive=None):
        self._case_insensitive = case_insensitive  # TODO: implement support for this
        self._fs = {}

    def upload(self, local_file, remote_file) -> tuple:
        with open(local_file, "rb") as x:
            contents = x.read()
        file = self._fs.get(remote_file, None)
        if file is None:
            file = MockProvider.File(remote_file)
            self._fs[remote_file] = file
        file.contents = contents
        return file.id, file.hash()

    def download(self, remote_file, local_file):
        contents = self._fs.get(remote_file, None)
        if contents is None:
            raise CloudFileNotFoundError(remote_file)
        with open(local_file, "wb") as x:
            x.write(contents)

    def rename(self, remote_file_from, remote_file_to):
        pass

    def delete(self, remote_file) -> bool:
        pass

    def exists(self, remote_file) -> bool:
        pass

    def local_hash(self, local_file):
        pass

    def hash(self, remote_file):
        pass

    def id(self, remote_file):
        pass

    def events(self):
        pass


@pytest.fixture
def manager():
    return EventManager(MockProvider())  # TODO extend this to take any provider


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
