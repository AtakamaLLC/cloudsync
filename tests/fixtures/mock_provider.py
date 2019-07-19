import time
from hashlib import md5
from collections import namedtuple
from typing import Dict
from pycloud.provider import Provider

from pycloud import CloudFileNotFoundError, CloudFileExistsError

MockProviderInfo = namedtuple('MockProviderInfo', 'oid hash path')


class MockProvider(Provider):
    connected = True
    # TODO: normalize names to get rid of trailing slashes, etc.

    class FSObject:         # pylint: disable=too-few-public-methods
        FILE = 'file'
        DIR = 'dir'

        def __init__(self, path, object_type, contents=None):
            # self.display_path = path  # TODO: used for case insensitive file systems
            if contents is None and type == MockProvider.FSObject.FILE:
                contents = b""
            self.path = path
            self.contents = contents
            self.oid = str(id(self))
            self.exists = True
            self.type = object_type

        def hash(self):
            return md5(self.contents).hexdigest()

    class Event:  # pylint: disable=too-few-public-methods
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
                           "old_path": self.old_object.path,
                           "path": self.new_object.path
                           }
            elif self.action == self.ACTION_MODIFY:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                           "hash": self.new_object.hash()
                           }
            elif self.action == self.ACTION_DELETE:
                ret_val = {"action": self.action,
                           "id": self.new_object.oid,
                           }

            return ret_val


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
        self._api()
        return self._fs_by_path.get(path, None)

    def _store_object(self, fo: "MockProvider.FSObject"):
        # TODO: support case insensitive storage
        self._fs_by_path[fo.path] = fo
        self._fs_by_oid[fo.oid] = fo

    def _delete_object(self, fo: "MockProvider.FSObject"):
        # so far, it looks like I don't need this, but here it is for your edification
        # instead, file objects get the exists flag set to false, and never truly disappear
        # TODO: do I need to check if the path and ID exist before del to avoid a key error,
        #  or perhaps just catch and swallow that exception? Whatever... this isn't used... yet
        del self._fs_by_path[fo.path]
        del self._fs_by_oid[fo.oid]

    def _api(self, *args, **kwargs):
        pass

    def events(self, timeout=1):
        # TODO: implement events
        self._api()
        self.walk()
        return []

    def walk(self):
        self._api()
        # TODO: implement walk
        self.walked = True

    def upload(self, oid, file_like):
        self._api()
        contents = file_like.read()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file.contents = contents
        return MockProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def create(self, path, file_like) -> 'MockProviderInfo':
        # TODO: check to make sure the folder exists before creating a file in it
        self._api()
        contents = file_like.read()
        file = self._get_by_path(path)
        if file is None:
            file = MockProvider.FSObject(path, MockProvider.FSObject.FILE)
            self._store_object(file)
        file.contents = contents
        return MockProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def download(self, oid, file_like):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file_like.write(file.contents)

    def rename(self, oid, path):
        self._api()
        # TODO: folders are implied by the path of the file...
        #  actually check to make sure the folder exists and raise a FileNotFound if not
        file_old = self._fs_by_oid.get(oid, None)
        file_new = self._get_by_path(path)
        if not (file_old and file_old.exists):
            raise CloudFileNotFoundError(oid)
        if file_new and file_new.exists:
            if self._allow_renames_over_existing:
                self.delete(file_new.oid)
            else:
                raise CloudFileExistsError(path)
        file_old.path = path
        self.delete(file_old.oid)
        self._store_object(file_old)

    def mkdir(self, path):
        # TODO: ensure parent folder exists
        self._api()
        file = self._get_by_path(path)
        if file and file.exists:
            raise CloudFileExistsError(path)
        new_fs_object = MockProvider.FSObject(path, MockProvider.FSObject.DIR)
        self._store_object(new_fs_object)

    def delete(self, oid):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        file.exists = False

    def exists_oid(self, oid):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        return file and file.exists

    def exists_path(self, path) -> bool:
        self._api()
        file = self._get_by_path(path)
        return file and file.exists

    @staticmethod
    def hash_data(file_like):
        contents = file_like.read()
        return md5(contents).hexdigest()

    def remote_hash(self, oid):
        self._api()
        file: MockProvider.FSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        return file.hash()

    def info_path(self, path):
        self._api()
        file: MockProvider.FSObject = self._get_by_path(path)
        if not (file and file.exists):
            raise CloudFileNotFoundError(path)
        return MockProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def info_oid(self, oid):
        self._api()
        file: MockProvider.FSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        return MockProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def hash_oid(self, oid):
        file = self._fs_by_oid.get(oid, None)
        return file and file.exists and file.hash()

    def is_sub_path(self, folder, target, sep=None, anysep=False, strict=False):
        if sep is None:
            if anysep:
                sep = "/"
                folder = folder.replace("\\", "/")
                target = target.replace("\\", "/")
            else:
                sep = self._sep
        # Will return True for is-same-path in addition to target
        folder_full = str(folder)
        folder_full = folder_full.rstrip(sep)
        target_full = str(target)
        target_full = target_full.rstrip(sep)
        # .lower() instead of normcase because normcase will also mess with separators
        if not self._case_sensitive:
            folder_full = folder_full.lower()
            target_full = target_full.lower()

        # target is same as folder, or target is a subpath (ensuring separator is there for base)
        if folder_full == target_full:
            return False if strict else sep
        elif len(target_full) > len(folder_full) and \
                target_full[len(folder_full)] == sep:
            if target_full.startswith(folder_full):
                return target_full.replace(folder_full, "", 1)
            else:
                return False
        return False

    def replace_path(self, path, from_dir, to_dir):
        relative = self.is_sub_path(path, from_dir)
        if relative:
            return to_dir + relative
        raise ValueError("replace_path used without subpath")


def test_mock_basic():
    """
    basic spot-check, more tests are in test_providers with mock as one of the providers
    """
    from io import BytesIO
    m = MockProvider()
    info = m.create("/hi.txt", BytesIO(b'hello'))
    assert info.hash
    assert info.oid
    b = BytesIO()
    m.download(info.oid, b)
    assert b.getvalue() == b'hello'
