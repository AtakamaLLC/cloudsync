import time
import copy
from hashlib import md5
from typing import Dict, List
from pycloud.event import Event
from pycloud.provider import Provider, ProviderInfo
from pycloud import CloudFileNotFoundError, CloudFileExistsError


class MockProvider(Provider):
    connected = True
    # TODO: normalize names to get rid of trailing slashes, etc.

    class FSObject:         # pylint: disable=too-few-public-methods
        FILE = 'mock file'
        DIR = 'mock dir'

        def __init__(self, path, object_type, contents=None):
            # self.display_path = path  # TODO: used for case insensitive file systems
            if contents is None and type == MockProvider.FSObject.FILE:
                contents = b""
            self.path = path
            self.contents = contents
            self.oid = str(id(self))
            self.exists = True
            self.type = object_type
            self.update()

        def hash(self) -> str:
            return md5(self.contents).hexdigest()

        def update(self):
            self.mtime = time.time()

    class MockEvent:  # pylint: disable=too-few-public-methods
        ACTION_CREATE = "provider create"
        ACTION_RENAME = "provider rename"
        ACTION_UPDATE = "provider modify"
        ACTION_DELETE = "provider delete"

        def __init__(self, action, target_object: "MockProvider.FSObject"):
            self.target_object = copy.copy(target_object)
            self.action = action
            self.timestamp = time.time()

        def serialize(self):
            ret_val = None
            target = self.target_object
            if self.action == self.ACTION_CREATE:
                ret_val = {"action": self.action,
                           "id": target.oid,
                           "mtime": target.mtime,
                           "path": target.path
                           }
            elif self.action == self.ACTION_RENAME:
                ret_val = {"action": self.action,
                           "id": target.oid,
                           "mtime": target.mtime,
                           "path": target.path
                           }
            elif self.action == self.ACTION_UPDATE:
                ret_val = {"action": self.action,
                           "id": target.oid,
                           "mtime": target.mtime,
                           "hash": target.hash()
                           }
            elif self.action == self.ACTION_DELETE:
                ret_val = {"action": self.action,
                           "mtime": target.mtime,
                           "id": target.oid,
                           }

            return ret_val

    def __init__(self, case_sensitive=True, allow_renames_over_existing=True, sep="/"):
        super().__init__()
        # TODO: implement locks around _fs_by_path, _fs_by_oid and _events...
        #  These will be accessed in a thread by the event manager
        self._fs_by_path: Dict[str, "MockProvider.FSObject"] = {}
        self._fs_by_oid: Dict[str, "MockProvider.FSObject"] = {}
        self._events: List["MockProvider.MockEvent"] = []
        self._latest_event = -1
        self._cursor = -1
        self._action_map = {
            MockProvider.MockEvent.ACTION_CREATE: Event.ACTION_CREATE,
            MockProvider.MockEvent.ACTION_RENAME: Event.ACTION_RENAME,
            MockProvider.MockEvent.ACTION_UPDATE: Event.ACTION_UPDATE,
            MockProvider.MockEvent.ACTION_DELETE: Event.ACTION_DELETE,
        }
        self._type_map = {
            MockProvider.FSObject.FILE
        }

    def _register_event(self, action, target_object):
        event = MockProvider.MockEvent(action, target_object)
        self._events.append(event)
        target_object.update()
        self._latest_event = len(self._events) - 1

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

    def translate_event(self, pe: "MockProvider.MockEvent") -> Event:
        event_type = self._action_map.get(pe.action, None)
        fs_obj = pe.target_object
        assert event_type
        return Event(event_type, fs_obj.type, )

    def _api(self, *args, **kwargs):
        pass

    def events(self, timeout=1):
        # TODO implement timeout
        self._api()
        while self._cursor < self._latest_event:
            self._cursor += 1
            provider_event = self._events[self._cursor]
            target = provider_event.target_object
            yield Event(Event.REMOTE, target.type, target.oid, target.path, target.hash(), target.exists)
        else:
            # This clause runs whenever the while condition becomes false, so at least once
            # after the loop ends, or in place of the loop if it never loops
            time.sleep(timeout)

    def walk(self):
        self._api()
        # TODO: implement walk
        for obj in self._fs_by_oid.values():
            yield Event(Event.REMOTE, obj.type, obj.oid, obj.path, obj.hash(), obj.exists)
        self.walked = True

    def upload(self, oid, file_like):
        self._api()
        contents = file_like.read()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file.contents = contents
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def create(self, path, file_like) -> 'ProviderInfo':
        # TODO: check to make sure the folder exists before creating a file in it
        self._api()
        contents = file_like.read()
        file = self._get_by_path(path)
        if file is None:
            file = MockProvider.FSObject(path, MockProvider.FSObject.FILE)
            self._store_object(file)
        file.contents = contents
        self._register_event(MockProvider.MockEvent.ACTION_CREATE, file)
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

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
        # TODO: folder renames must rename all children as well
        #  store a parent id in the FSObject, then folder renames can walk through _fs, looking for parent id
        #  matches and rename all those
        file_old = self._fs_by_oid.get(oid, None)
        file_new = self._get_by_path(path)
        if file_old.path == path:
            return
        if not (file_old and file_old.exists):
            raise CloudFileNotFoundError(oid)
        if file_new and file_new.exists:
            if self._allow_renames_over_existing:
                self.delete(file_new.oid)
            else:
                raise CloudFileExistsError(path)
        self._delete_object(file_old)
        file_old.path = path
        self._store_object(file_old)
        self._register_event(MockProvider.MockEvent.ACTION_RENAME, file_old)  # file_old has been updated by this point

    def mkdir(self, path) -> str:
        # TODO: ensure parent folder exists
        self._api()
        file = self._get_by_path(path)
        if file and file.exists:
            raise CloudFileExistsError(path)
        new_fs_object = MockProvider.FSObject(path, MockProvider.FSObject.DIR)
        self._store_object(new_fs_object)
        self._register_event(MockProvider.MockEvent.ACTION_CREATE, new_fs_object)
        return new_fs_object.oid

    def delete(self, oid):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        file.exists = False
        self._register_event(MockProvider.MockEvent.ACTION_DELETE, file)

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
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def info_oid(self, oid):
        self._api()
        file: MockProvider.FSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            raise CloudFileNotFoundError(oid)
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def hash_oid(self, oid):
        file = self._fs_by_oid.get(oid, None)
        return file and file.exists and file.hash()

    # @staticmethod
    # def _slurp(path):
    #     with open(path, "rb") as x:
    #         return x.read()
    #
    # @staticmethod
    # def _burp(path, contents):
    #     with open(path, "wb") as x:
    #         x.write(contents)


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
