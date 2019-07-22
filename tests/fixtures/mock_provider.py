import time
import copy
import logging
from hashlib import md5
from typing import Dict, List

from cloudsync.event import Event
from cloudsync.provider import Provider, ProviderInfo
from cloudsync import CloudFileNotFoundError, CloudFileExistsError

log = logging.getLogger(__name__)

# TODO: ensure parent folder exists prior to create
# TODO: rename children when renaming non-empty folder

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
            if self.type == self.DIR:
                return None
            return md5(self.contents).hexdigest()

        def update(self):
            self.mtime = time.time()

    class MockEvent():  # pylint: disable=too-few-public-methods
        ACTION_CREATE = "provider create"
        ACTION_RENAME = "provider rename"
        ACTION_UPDATE = "provider modify"
        ACTION_DELETE = "provider delete"

        def __init__(self, action, target_object: "MockProvider.FSObject"):
            self._target_object = copy.copy(target_object)
            self._action = action
            self._timestamp = time.time()

        def serialize(self):
            ret_val = {"action": self._action,
                       "id": self._target_object.oid,
                       "object type": self._target_object.type,
                       "mtime": self._target_object.mtime,
                       "trashed": not self._target_object.exists,
                       }
            return ret_val

    def __init__(self, case_sensitive=True, allow_renames_over_existing=True, sep="/"):
        super().__init__()
        # TODO: implement locks around _fs_by_path, _fs_by_oid and _events...
        #  These will be accessed in a thread by the event manager
        self.case_sensitive = case_sensitive
        self.allow_renames_over_existing = allow_renames_over_existing
        self.sep = sep
        self._fs_by_path: Dict[str, "MockProvider.FSObject"] = {}
        self._fs_by_oid: Dict[str, "MockProvider.FSObject"] = {}
        self._events: List["MockProvider.MockEvent"] = []
        self._latest_event = -1
        self._cursor = -1
        self._type_map = {
            MockProvider.FSObject.FILE: Event.TYPE_FILE,
            MockProvider.FSObject.DIR: Event.TYPE_DIRECTORY,
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

    def _unstore_object(self, fo: "MockProvider.FSObject"):
        # TODO: do I need to check if the path and ID exist before del to avoid a key error,
        #  or perhaps just catch and swallow that exception?
        del self._fs_by_path[fo.path]
        del self._fs_by_oid[fo.oid]

    def _translate_event(self, pe: "MockProvider.MockEvent") -> Event:
        event = pe.serialize()
        provider_type = event.get("object type", None)
        standard_type = self._type_map.get(provider_type, None)
        assert standard_type
        oid = event.get("id", None)
        mtime = event.get("mtime", None)
        trashed = event.get("trashed", None)
        retval = Event(standard_type, oid, None, None, not trashed, mtime)
        return retval

    def _api(self, *args, **kwargs):
        pass

    def events(self, timeout=1):
        # TODO implement timeout
        self._api()
        done = False
        end_time = time.monotonic() + timeout
        found = False
        while not done:
            if self._cursor < self._latest_event:
                self._cursor += 1
                pe = self._events[self._cursor]
                yield self._translate_event(pe)
                found = True
            else:
                done = found or time.monotonic() >= end_time
                if not done:
                    time.sleep(.1)

    def walk(self):
        self._api()
        # TODO: implement walk
        now = time.time()
        for obj in self._fs_by_oid.values():
            yield Event(obj.type, obj.oid, obj.path, obj.hash(), obj.exists, now)
        self.walked = True

    def upload(self, oid, file_like):
        self._api()
        contents = file_like.read()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        if file.type != MockProvider.FSObject.FILE:
            raise CloudFileExistsError("Only files may be uploaded, and %s is not a file" % file.path)
        file.contents = contents
        self._register_event(MockProvider.MockEvent.ACTION_UPDATE, file)
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def create(self, path, file_like) -> 'ProviderInfo':
        # TODO: check to make sure the folder exists before creating a file in it
        self._api()
        contents = file_like.read()
        file = self._get_by_path(path)
        if file is None:
            parent_path = self.dirname(path)
            parent_obj = self._get_by_path(parent_path)
            if parent_obj is None or parent_obj.type != MockProvider.FSObject.DIR:
                # perhaps this should separate "FileNotFound" and "non-folder parent exists
                # and raise different exceptions
                raise CloudFileNotFoundError(parent_path)
            file = MockProvider.FSObject(path, MockProvider.FSObject.FILE)
            self._store_object(file)
        if file.type != MockProvider.FSObject.FILE:
            raise CloudFileExistsError("Only files may be uploaded, and %s is not a file" % file.path)
        file.contents = contents
        log.debug("created %s %s", file.oid, file.type)
        self._register_event(MockProvider.MockEvent.ACTION_CREATE, file)
        return ProviderInfo(oid=file.oid, hash=file.hash(), path=file.path)

    def download(self, oid, file_like):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if file is None:
            raise CloudFileNotFoundError(oid)
        file_like.write(file.contents)

    def rename(self, oid, new_path):
        log.debug("renaming %s", oid)
        self._api()
        # TODO: folders are implied by the path of the file...
        #  actually check to make sure the folder exists and raise a FileNotFound if not
        object_to_rename = self._fs_by_oid.get(oid, None)
        possible_conflict = self._get_by_path(new_path)
        if self.paths_match(object_to_rename.path, new_path):
            if not self.allow_renames_over_existing:
                raise CloudFileExistsError(new_path)
            else:
                log.debug("noop rename file %s to itself", oid)
                return
        if not (object_to_rename and object_to_rename.exists):
            raise CloudFileNotFoundError(oid)
        parent_path = self.dirname(new_path)
        parent_obj = self._get_by_path(parent_path)
        if parent_obj is None or not parent_obj.exists or parent_obj.type != MockProvider.FSObject.DIR:
            raise CloudFileNotFoundError(parent_path)
        if possible_conflict and possible_conflict.exists:
            if possible_conflict.type != object_to_rename.type:
                log.debug("rename %s:%s conflicts with existing object of another type", oid, object_to_rename.path)
                raise CloudFileExistsError(new_path)
            if not self.allow_renames_over_existing:
                log.debug("rename %s:%s conflicts with existing", oid, object_to_rename.path)
                raise CloudFileExistsError(new_path)
            else:
                self.delete(possible_conflict.oid)
        if object_to_rename.type == MockProvider.FSObject.FILE:
            self._rename_single_object(object_to_rename, new_path)
        else:  # object to rename is a directory
            # TODO: folder renames must rename all children as well
            #  store a parent id in the FSObject, then folder renames can walk through _fs, looking for parent id
            #  matches and rename all those
            for obj in self._fs_by_oid.values():
                if self.is_sub_path(object_to_rename.path, obj.path):
                    new_obj_path = self.replace_path(obj.path, object_to_rename.path, new_path)
                    self._rename_single_object(obj, new_obj_path)
            assert NotImplementedError()
        self._register_event(MockProvider.MockEvent.ACTION_RENAME, object_to_rename)

    def _rename_single_object(self, source_object: "MockProvider.FSObject", destination_path):
        # This will assume all validation has already been done, and just rename the thing
        # without trying to rename contents of folders, just rename the object itself
        log.debug("renaming %s to %s", source_object.path, destination_path)
        self._unstore_object(source_object)
        source_object.path = destination_path
        self._store_object(source_object)
        self._register_event(MockProvider.MockEvent.ACTION_RENAME, source_object)
        log.debug("rename complete %s", source_object.path)

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
        return file is not None and file.exists

    def exists_path(self, path) -> bool:
        self._api()
        file = self._get_by_path(path)
        return file is not None and file.exists

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

    def dirname(self, path: str):
        norm_path = self.normalize_path(path)
        parts = split(r'[%s]+' % self.sep, norm_path)
        retval = self.sep + self.sep.join(parts[0:-1])
        return retval


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
