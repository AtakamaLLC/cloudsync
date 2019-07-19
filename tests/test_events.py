import pytest
import os
import copy
from hashlib import md5
from collections import namedtuple, deque

from pycloud import EventManager, CloudFileNotFoundError, CloudFileExistsError

MockProviderUploadReturnType = namedtuple('MockProviderUploadReturnType', 'remote_id hash')


class MockProvider:
    # TODO: normalize names to get rid of trailing slashes, etc.
    class FSObject:
        FILE = 'file'
        DIR = 'dir'
        def __init__(self, name, type, contents=None):
            # self.display_name = name  # TODO: used for case insensitive file systems
            if contents is None and type == MockProvider.FSObject.FILE:
                contents = b""
            self.name = name
            self.contents = contents
            self.remote_id = str(id(self))
            self.exists = True
            self.type = type

        def hash(self):
            return md5(self.contents).hexdigest()

    class Event:
        ACTION_CREATE = "create"
        ACTION_RENAME = "rename"
        ACTION_MODIFY = "modify"
        ACTION_DELETE = "delete"

        def __init__(self, old_object: "MockProvider.FSObject", new_object: "MockProvider.FSObject", action):
            self.old_object = old_object
            self.new_object = new_object
            self.action = action

        def serialize(self):
            ret_val = None
            if self.action == self.ACTION_CREATE:
                ret_val = {"action": self.action,
                          "id": self.new_object.remote_id,
                          "path": self.new_object.name
                          }
            elif self.action == self.ACTION_RENAME:
                ret_val = {"action": self.action,
                           "id": self.new_object.remote_id,
                           "path": self.new_object.name
                          }
            elif self.action == self.ACTION_MODIFY:
                ret_val = {"action": self.action,
                           "id": self.new_object.remote_id,
                          }
            elif self.action == self.ACTION_DELETE:
                ret_val = {"action": self.action,
                           "id": self.new_object.remote_id,
                          }


            return ret_val


    def __init__(self, case_sensitive=True, allow_renames_over_existing=True):
        self._case_sensitive = case_sensitive  # TODO: implement support for this
        self._allow_renames_over_existing = allow_renames_over_existing
        self._fs = {}
        self._events = []
        self._event_cursor = 0

    @staticmethod
    def _slurp(path):
        with open(path, "rb") as x:
            return x.read()

    @staticmethod
    def _burp(path, contents):
        with open(path, "wb") as x:
            x.write(contents)

    def _register_event(self, action, old_object, new_object):


    def upload(self, local_file, remote_file) -> 'MockProviderUploadReturnType':
        # TODO: check to make sure the folder exists before creating a file in it
        contents = self._slurp(local_file)
        file = self._fs.get(remote_file, None)
        if file is None:
            file = MockProvider.FSObject(remote_file, MockProvider.FSObject.FILE)
            self._fs[remote_file] = file
        file.contents = contents
        return MockProviderUploadReturnType(remote_id=file.remote_id, hash=file.hash())

    def download(self, remote_file, local_file):
        file = self._fs.get(remote_file, None)
        if file is None:
            raise CloudFileNotFoundError(remote_file)
        self._burp(local_file, file.contents)
        with open(local_file, "wb") as x:
            x.write(file.contents)

    def rename(self, remote_file_from, remote_file_to):
        #TODO: folders are implied by the name of the file...
        # actually check to make sure the folder exists and raise a FileNotFound if not
        file_old = self._fs.get(remote_file_from, None)
        file_new = self._fs.get(remote_file_to, None)
        if not (file_old and file_old.exists):
            raise CloudFileNotFoundError(remote_file_from)
        if file_new and file_new.exists and not self._allow_renames_over_existing:
            raise CloudFileExistsError(remote_file_to)
        file_old.name = remote_file_to
        self._fs[remote_file_to] = file_old

    def mkdir(self, remote_dir):
        #TODO: ensure parent folder exists
        file = self._fs.get(remote_dir, None)
        if file and file.exists:
            raise CloudFileExistsError(remote_dir)
        self._fs[remote_dir] = MockProvider.FSObject(remote_dir, MockProvider.FSObject.DIR)

    def delete(self, remote_file):
        file = self._fs.get(remote_file, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(remote_file)
        file.exists = False

    def exists(self, remote_file) -> bool:
        file = self._fs.get(remote_file, None)
        return file and file.exists

    def local_hash(self, local_file):
        contents = self._slurp(local_file)
        return md5(contents).hexdigest()

    def remote_hash(self, remote_file):
        file: MockProvider.FSObject = self._fs.get(remote_file, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(remote_file)
        return file.hash()

    def remote_id(self, remote_file):
        file: MockProvider.FSObject = self._fs.get(remote_file, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(remote_file)
        return file.remote_id

    def events(self):
        pass

    def remote_id_to_path(self, remote_id):
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
