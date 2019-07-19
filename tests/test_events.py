import pytest
import os
import copy
import time
from hashlib import md5
from collections import namedtuple, deque

from pycloud import EventManager, CloudFileNotFoundError, CloudFileExistsError

MockProviderInfo = namedtuple('MockProviderInfo', 'oid hash')


class MockProvider:
    # TODO: normalize names to get rid of trailing slashes, etc.
    class FSObject:
        FILE = 'file'
        DIR = 'dir'

        def __init__(self, path, type, contents=None):
            # self.display_path = path  # TODO: used for case insensitive file systems
            if contents is None and type == MockProvider.FSObject.FILE:
                contents = b""
            self.path = path
            self.contents = contents
            self.oid = str(id(self))
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
            self.timestamp = time.time()

        def serialize(self):
            ret_val = None
            if self.action == self.ACTION_CREATE:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                           "path": self.new_object.path
                          }
            elif self.action == self.ACTION_RENAME:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                           "path": self.new_object.path
                          }
            elif self.action == self.ACTION_MODIFY:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                          }
            elif self.action == self.ACTION_DELETE:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                          }

            return ret_val

    def __init__(self, case_sensitive=True, allow_renames_over_existing=True):
        self._case_sensitive = case_sensitive  # TODO: implement support for this
        self._allow_renames_over_existing = allow_renames_over_existing
        self._fs_by_path = {}
        self._fs_by_oid = {}
        self._events = []
        self._event_cursor = 0

    # @staticmethod
    # def _slurp(path):
    #     with open(path, "rb") as x:
    #         return x.read()
    #
    # @staticmethod
    # def _burp(path, contents):
    #     with open(path, "wb") as x:
    #         x.write(contents)

    def _register_event(self, action, old_object, new_object):
        pass

    def _get_by_path(self, path):
        # TODO: normalize the path, support case insensitive lookups, etc
        return self._fs_by_path.get(path, None)

    def _store_object(self, fo: "MockProvider.FSObject"):
        # TODO: support case insensitive storage
        self._fs_by_path[fo.path] = fo
        self._fs_by_oid[fo.oid] = fo

    def _delete_object(self, fo: "MockProvider.FSObject"):
        # so far, it looks like I don't need this, but here it is for your edification
        # instead, file objects get the exists flag set to false, and never truly disappear
        del self._fs_by_path[fo.path]
        del self._fs_by_oid[fo.oid]

    def upload(self, oid, file_like):
        contents = file_like.read()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file.contents = contents
        return MockProviderInfo(oid=file.oid, hash=file.hash())

    def create(self, path, file_like) -> 'MockProviderInfo':
        # TODO: check to make sure the folder exists before creating a file in it
        contents = file_like.read()
        file = self._fs_by_path.get(path, None)
        if file is None:
            file = MockProvider.FSObject(path, MockProvider.FSObject.FILE)
            self._store_object(file)
        file.contents = contents
        return MockProviderInfo(oid=file.oid, hash=file.hash())

    def download(self, oid, file_like):
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file_like.write(file.contents)

    def rename(self, oid, path):
        #TODO: folders are implied by the path of the file...
        # actually check to make sure the folder exists and raise a FileNotFound if not
        file_old = self._fs_by_oid.get(oid, None)
        file_new = self._fs_by_path.get(path, None)
        if not (file_old and file_old.exists):
            raise CloudFileNotFoundError(oid)
        if file_new and file_new.exists:
            if self._allow_renames_over_existing:
                self.delete(file_new.oid)
            else:
                raise CloudFileExistsError(path)
        old_path = file_old.path
        file_old.path = path
        self.delete(file_old.oid)
        self._fs_by_path[path] = file_old

    def mkdir(self, path):
        #TODO: ensure parent folder exists
        file = self._fs_by_path.get(path, None)
        if file and file.exists:
            raise CloudFileExistsError(path)
        new_fs_object = MockProvider.FSObject(path, MockProvider.FSObject.DIR)
        self._store_object(new_fs_object)

    def delete(self, oid):
        file = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        file.exists = False

    def exists_oid(self, oid):
        file = self._fs_by_oid.get(oid, None)
        return file and file.exists

    def exists_path(self, path) -> bool:
        file = self._fs_by_path.get(path, None)
        return file and file.exists

    @staticmethod
    def hash_data(file_like):
        contents = file_like.read()
        return md5(contents).hexdigest()

    def remote_hash(self, oid):
        file: MockProvider.FSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        return file.hash()

    def events(self):
        pass

    def info_path(self, path):
        file: MockProvider.FSObject = self._fs_by_path.get(path, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(path)
        return MockProviderInfo(oid=file.oid, hash=file.hash())

    def info_oid(self, oid):
        file: MockProvider.FSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        return MockProviderInfo(oid=file.oid, hash=file.hash())


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
