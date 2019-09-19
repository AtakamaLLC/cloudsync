import os
import time
import copy
import logging
from hashlib import md5
from typing import Dict, List, Any, Optional, Generator

import pytest

from cloudsync.event import Event
from cloudsync.provider import Provider
from cloudsync.types import OInfo, OType, DirInfo
from cloudsync.exceptions import CloudFileNotFoundError, CloudFileExistsError, CloudTokenError, \
    CloudDisconnectedError, CloudCursorError

log = logging.getLogger(__name__)


class MockFSObject:         # pylint: disable=too-few-public-methods
    FILE = 'mock file'
    DIR = 'mock dir'

    def __init__(self, path, object_type, oid_is_path, contents=None, mtime=None):
        # self.display_path = path  # TODO: used for case insensitive file systems
        if contents is None and type == MockFSObject.FILE:
            contents = b""
        self.path = path.rstrip("/")
        self.contents = contents
        self.oid = path if oid_is_path else str(id(self))
        self.exists = True
        self.type = object_type

        if self.type == self.FILE:
            # none is not valid for empty file
            if self.contents is None:
                self.contents = b''

        self.mtime = mtime or time.time()

    @property
    def otype(self):
        if self.type == self.FILE:
            return OType.FILE
        else:
            return OType.DIRECTORY

    def hash(self) -> Optional[bytes]:
        if self.type == self.DIR:
            return None
        return md5(self.contents).digest()

    def update(self):
        self.mtime = time.time()

    def copy(self):
        return copy.copy(self)

    def __repr__(self):
        return "MockFSObject: %s(%s) %s %s %s" % (self.path, len(self.contents or ""), self.oid, self.exists, self.type)


class MockEvent:  # pylint: disable=too-few-public-methods
    ACTION_CREATE = "provider create"
    ACTION_RENAME = "provider rename"
    ACTION_UPDATE = "provider modify"
    ACTION_DELETE = "provider delete"

    def __init__(self, action, target_object: MockFSObject, prior_oid=None):
        self._target_object = copy.copy(target_object)
        self._action = action
        self._prior_oid = prior_oid
        self._timestamp = time.time()

    def serialize(self):
        ret_val = {"action": self._action,
                   "id": self._target_object.oid,
                   "object type": self._target_object.type,
                   "path": self._target_object.path,
                   "mtime": self._target_object.mtime,
                   "prior_oid": self._prior_oid,
                   "trashed": not self._target_object.exists,
                   }
        return ret_val


class MockProvider(Provider):
    default_sleep = 0.01
    connected = True
    name = "Mock"
    # TODO: normalize names to get rid of trailing slashes, etc.

    def __init__(self, oid_is_path: bool, case_sensitive: bool):
        """Constructor for MockProvider

        :param oid_is_path: Act as a filesystem or other oid-is-path provider
        :param case_sensitive: Paths are case sensistive
        """
        super().__init__()
        log.debug("mock mode: o:%s, c:%s", oid_is_path, case_sensitive)
        self.oid_is_path = oid_is_path
        self.case_sensitive = case_sensitive
        self._fs_by_path: Dict[str, MockFSObject] = {}
        self._fs_by_oid: Dict[str, MockFSObject] = {}
        self._events: List[MockEvent] = []
        self._latest_cursor = -1
        self._cursor = -1
        self._type_map = {
            MockFSObject.FILE: OType.FILE,
            MockFSObject.DIR: OType.DIRECTORY,
        }
        self.event_timeout = 1
        self.event_sleep = 0.001
        self.creds = {"key": "val"}
        self.connection_id = os.urandom(2).hex()

    def disconnect(self):
        self.connected = False

    def reconnect(self):
        if not self.creds:
            raise CloudTokenError()
        self.connected = True

    def _register_event(self, action, target_object, prior_oid=None):
        event = MockEvent(action, target_object, prior_oid)
        self._events.append(event)
        target_object.update()
        self._latest_cursor = len(self._events) - 1

    def _get_by_oid(self, oid):
        self._api()
        return self._fs_by_oid.get(oid, None)

    def normalize(self, path):
        if self.case_sensitive:
            return path
        else:
            return path.lower()

    def _get_by_path(self, path):
        path = self.normalize(path)
        # TODO: normalize the path, support case insensitive lookups, etc
        self._api()
        return self._fs_by_path.get(path, None)

    def _store_object(self, fo: MockFSObject):
        # TODO: support case insensitive storage
        assert fo.path == fo.path.rstrip("/")
        self._fs_by_path[self.normalize(fo.path)] = fo
        self._fs_by_oid[fo.oid] = fo

    def _unstore_object(self, fo: MockFSObject):
        # TODO: do I need to check if the path and ID exist before del to avoid a key error,
        #  or perhaps just catch and swallow that exception?
        del self._fs_by_path[self.normalize(fo.path)]
        del self._fs_by_oid[fo.oid]

    def _translate_event(self, pe: MockEvent, cursor) -> Event:
        event = pe.serialize()
        provider_type = event.get("object type", None)
        standard_type = self._type_map.get(provider_type, None)
        assert standard_type
        oid = event.get("id", None)
        mtime = event.get("mtime", None)
        trashed = event.get("trashed", None)
        prior_oid = event.get("prior_oid", None)
        path = None
        if self.oid_is_path:
            path = event.get("path")
        retval = Event(standard_type, oid, path, None, not trashed, mtime, prior_oid, new_cursor=cursor)
        return retval

    def _api(self, *args, **kwargs):
        if not self.connected:
            raise CloudDisconnectedError()
        pass

    @property
    def latest_cursor(self):
        return self._latest_cursor

    @property
    def current_cursor(self):
        return self._cursor

    @current_cursor.setter
    def current_cursor(self, val):
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, int) and val is not None:
            raise CloudCursorError(val)
        self._cursor = val

    def events(self) -> Generator[Event, None, None]:
        self._api()
#        log.error("GETTING EVENTS : %s", self._cursor)
        while self._cursor < self._latest_cursor:
            self._cursor += 1
            pe = self._events[self._cursor]
            yield self._translate_event(pe, self._cursor)

    def walk(self, path, since=None):
        # TODO: implement "since" parameter
        self._api()
        for obj in list(self._fs_by_oid.values()):
            if self.is_subpath(path, obj.path, strict=False):
                yield Event(obj.otype, obj.oid, obj.path, obj.hash(), obj.exists, obj.mtime)

    def upload(self, oid, file_like, metadata=None) -> OInfo:
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if file is None or not file.exists:
            raise CloudFileNotFoundError(oid)
        if file.type != MockFSObject.FILE:
            raise CloudFileExistsError("Only files may be uploaded, and %s is not a file" % file.path)
        contents = file_like.read()
        file.contents = contents
        self._register_event(MockEvent.ACTION_UPDATE, file)
        return OInfo(otype=file.otype, oid=file.oid, hash=file.hash(), path=file.path)

    def listdir(self, oid) -> Generator[DirInfo, None, None]:
        folder_obj = self._get_by_oid(oid)
        if not (folder_obj and folder_obj.exists and folder_obj.type == MockFSObject.DIR):
            raise CloudFileNotFoundError(oid)
        path = folder_obj.path
        for obj in self._fs_by_oid.values():
            if obj.exists:
                relative = self.is_subpath(path, obj.path, strict=True)
                if relative:
                    relative = relative.lstrip("/")
                    if "/" not in relative:
                        yield DirInfo(otype=obj.otype, oid=obj.oid, hash=obj.hash(), path=obj.path, name=relative)

    def create(self, path, file_like, metadata=None) -> OInfo:
        # TODO: store the metadata
        file = self._get_by_path(path)
        if file is not None and file.exists:
            raise CloudFileExistsError("Cannot create, '%s' already exists" % file.path)
        self._verify_parent_folder_exists(path)
        if file is None or not file.exists:
            file = MockFSObject(path, MockFSObject.FILE, self.oid_is_path)
        file.contents = file_like.read()
        file.exists = True
        self._store_object(file)

        log.debug("created %s %s", file.oid, file.type)
        self._register_event(MockEvent.ACTION_CREATE, file)
        return OInfo(otype=file.otype, oid=file.oid, hash=file.hash(), path=file.path)

    def download(self, oid, file_like):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        if file is None or file.exists is False:
            raise CloudFileNotFoundError(oid)
        if file.type == MockFSObject.DIR:
            raise CloudFileExistsError("is a directory")
        file_like.write(file.contents)

    def rename(self, oid, path) -> str:
        log.debug("renaming %s -> %s", oid, path)
        self._api()
        # TODO: folders are implied by the path of the file...
        #  actually check to make sure the folder exists and raise a FileNotFound if not
        object_to_rename = self._fs_by_oid.get(oid, None)

        if not (object_to_rename and object_to_rename.exists):
            raise CloudFileNotFoundError(oid)

        possible_conflict = self._get_by_path(path)

        if possible_conflict and possible_conflict.oid == oid:
            possible_conflict = None

        self._verify_parent_folder_exists(path)
        if possible_conflict and possible_conflict.exists:
            if possible_conflict.type != object_to_rename.type:
                log.debug("rename %s:%s conflicts with existing object of another type", oid, object_to_rename.path)
                raise CloudFileExistsError(path)
            if possible_conflict.type == MockFSObject.DIR:
                try:
                    next(self.listdir(possible_conflict.oid))
                    raise CloudFileExistsError(path)
                except StopIteration:
                    pass  # Folder is empty, rename over it no problem
            else:
                raise CloudFileExistsError(path)
            log.debug("secretly deleting empty folder %s", path)
            self.delete(possible_conflict.oid)

        if object_to_rename.path == path:
            return oid

        prior_oid = None
        if self.oid_is_path:
            prior_oid = object_to_rename.oid

        if object_to_rename.type == MockFSObject.FILE:
            self._rename_single_object(object_to_rename, path, event=True)
        else:  # object to rename is a directory
            old_path = object_to_rename.path
            for obj in set(self._fs_by_oid.values()):
                if self.is_subpath(old_path, obj.path, strict=True):
                    new_obj_path = self.replace_path(obj.path, old_path, path)
                    self._rename_single_object(obj, new_obj_path, event=False)
            # only parent generates event
            self._rename_single_object(object_to_rename, path, event=True)

        if self.oid_is_path:
            assert object_to_rename.oid != prior_oid, "rename %s to %s" % (prior_oid, path)
        else:
            assert object_to_rename.oid == oid, "rename %s to %s" % (object_to_rename.oid, oid)

        return object_to_rename.oid

    def _rename_single_object(self, source_object: MockFSObject, destination_path, *, event):
        destination_path = destination_path.rstrip("/")
        # This will assume all validation has already been done, and just rename the thing
        # without trying to rename contents of folders, just rename the object itself
        log.debug("renaming %s to %s", source_object.path, destination_path)
        prior_oid = source_object.oid if self.oid_is_path else None
        self._unstore_object(source_object)
        source_object.path = destination_path
        if self.oid_is_path:
            source_object.oid = destination_path
        self._store_object(source_object)
        self._register_event(MockEvent.ACTION_RENAME, source_object, prior_oid)
        log.debug("rename complete %s", source_object.path)
        self.log_debug_state()

    def mkdir(self, path) -> str:
        self._verify_parent_folder_exists(path)
        file = self._get_by_path(path)
        if file and file.exists:
            if file.type == MockFSObject.FILE:
                raise CloudFileExistsError(path)
            else:
                log.debug("Skipped creating already existing folder: %s", path)
                return file.oid
        new_fs_object = MockFSObject(path, MockFSObject.DIR, self.oid_is_path)
        self._store_object(new_fs_object)
        self._register_event(MockEvent.ACTION_CREATE, new_fs_object)
        return new_fs_object.oid

    def delete(self, oid):
        return self._delete(oid)

    def _delete(self, oid, without_event=False):
        log.debug("delete %s", oid)
        self._api()
        file = self._fs_by_oid.get(oid, None)
        log.debug("got %s", file)
        if file and file.exists:
            if file.otype == OType.DIRECTORY:
                try:
                    next(self.listdir(file.oid))
                    raise CloudFileExistsError("Cannot delete non-empty folder %s:%s" % (oid, file.path))
                except StopIteration:
                    pass  # Folder is empty, delete it no problem
        else:
            path = file.path if file else "<UNKNOWN>"
            log.debug("Deleting non-existent oid %s:%s ignored", oid, path)
            return
        file.exists = False
        # todo: rename on top of another file needs to be allowed... and not require deletes
        # until mock provider supports this... we need a "special delete"
        # for tests that test this behavior
        if not without_event:
            self._register_event(MockEvent.ACTION_DELETE, file)

    def exists_oid(self, oid):
        self._api()
        file = self._fs_by_oid.get(oid, None)
        return file is not None and file.exists

    def exists_path(self, path) -> bool:
        file = self._get_by_path(path)
        return file is not None and file.exists

    def hash_oid(self, oid) -> Any:
        file = self._fs_by_oid.get(oid, None)
        if file and file.exists:
            return file.hash()
        else:
            return None

    @staticmethod
    def hash_data(file_like) -> bytes:
        return md5(file_like.read()).digest()

    def info_path(self, path: str) -> Optional[OInfo]:
        file: MockFSObject = self._get_by_path(path)
        if not (file and file.exists):
            return None
        return OInfo(otype=file.otype, oid=file.oid, hash=file.hash(), path=file.path)

    def info_oid(self, oid, use_cache=True) -> Optional[OInfo]:
        self._api()
        file: MockFSObject = self._fs_by_oid.get(oid, None)
        if not (file and file.exists):
            return None
        return OInfo(otype=file.otype, oid=file.oid, hash=file.hash(), path=file.path)

    # @staticmethod
    # def _slurp(path):
    #     with open(path, "rb") as x:
    #         return x.read()
    #
    # @staticmethod
    # def _burp(path, contents):
    #     with open(path, "wb") as x:
    #         x.write(contents)

    def log_debug_state(self, msg=""):
        files = list(self.walk("/"))
        log.debug("%s: mock provider state %s:%s", msg, len(files), files)

###################


def mock_provider_instance(oid_is_path, case_sensitive):
    prov = MockProvider(oid_is_path, case_sensitive)
    prov.event_timeout = 1
    prov.event_sleep = 0.001
    return prov


@pytest.fixture(params=[(False, True), (True, True)], ids=["mock_oid_cs", "mock_path_cs"])
def mock_provider(request):
    return mock_provider_instance(*request.param)


@pytest.fixture(params=[(False, True), (True, True)], ids=["mock_oid_cs", "mock_path_cs"])
def mock_provider_generator(request):
    return lambda oid_is_path=None, case_sensitive=None: \
        mock_provider_instance(
            request.param[0] if oid_is_path is None else oid_is_path,
            request.param[1] if case_sensitive is None else case_sensitive)

@pytest.fixture
def mock_provider_creator():
    return mock_provider_instance

def test_mock_basic():
    """
    basic spot-check, more tests are in test_providers with mock as one of the providers
    """
    from io import BytesIO
    m = MockProvider(False, True)
    info = m.create("/hi.txt", BytesIO(b'hello'))
    assert info.hash
    assert info.oid
    b = BytesIO()
    m.download(info.oid, b)
    assert b.getvalue() == b'hello'
