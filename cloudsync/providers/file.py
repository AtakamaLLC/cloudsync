import os
import sys
import glob
import re
import tempfile
import logging
import shutil
import collections
import threading
from hashlib import blake2s
import typing
from dataclasses import dataclass

from cloudsync.event import Event
from cloudsync.provider import Provider
from cloudsync.registry import register_provider
from cloudsync.types import OInfo, OType, DirInfo
import cloudsync.exceptions as ex


def is_osx():
    return sys.platform == "darwin"


if is_osx():
    from Foundation import NSURL  # pylint: disable=import-error,no-name-in-module


log = logging.getLogger(__name__)


def get_hash(dat):
    """Returns a hash of it's argument which can be a bytes or filelike object"""
    if not hasattr(dat, "read"):
        return blake2s(dat).digest()
    blocksize = 4096
    d = blake2s()
    block = dat.read(blocksize)
    while block:
        d.update(block)
        block = dat.read(blocksize)
    return d.digest()


def detect_case_sensitive(tmpdir=None):
    """Returns true if temp direcory specified is case sensitive, or gettempdir() if unspecified."""
    if not tmpdir:
        tmpdir = tempfile.gettempdir()
    f1 = os.path.join(tmpdir, "tmp." + os.urandom(16).hex())
    with open(f1, "w") as f:
        f.write("x")
    try:
        f2 = f1.upper()
        if os.path.exists(f2):
            return False
    finally:
        os.unlink(f1)
    return True


def casedpath(path):
    """Fixes the case of a file to the name on disk.

    Works only for a path that exists
    """
    if is_osx():
        url = NSURL.fileURLWithPath_(path)  # will be None if path doesn't exist
        if not url:
            return path
        return url.fileReferenceURL().path()

    r = glob.glob(re.sub(r'([^:/\\])(?=[/\\]|$)', r'[\1]', path))
    return r[0] if r else path


def canonicalize_fpath(case_sensitive: bool, full_path: str) -> str:
    """Fixes the case of a path - parent folder must exist."""
    if not case_sensitive:
        # not needed for case sensitive installations
        return full_path

    if not os.path.exists(full_path):
        # casedpath function doesn't work if the path doesn't exist
        fdir, fname = os.path.split(full_path)
        cp = casedpath(fdir)
        fp: typing.Optional[str]
        if cp:
            fp = os.path.join(cp, fname)
        else:
            log.error("unexpected call to canonicalized with missing parent folder", stack_info=True)
            fp = None
    else:
        fp = casedpath(full_path)  # canonicalizes path to an existing file

    if not fp:
        log.debug("canonicalize doesn't yet support missing parent folders %s", full_path)
        return full_path

    return fp


@dataclass
class CacheEnt:
    mtime = 0.0
    qhash = b''
    fhash = b''


class FileSystemProvider(Provider):
    """
    FileSystemProvider is a provider that uses the filesystem, and full paths as the storage location.
    """
    default_sleep = 0.01
    name = "filesystem"
    oid_is_path = True
    case_sensitive = detect_case_sensitive()
    _max_queue = 10000
    _test_event_timeout = 1
    _test_event_sleep = 0.001
    _test_creds = {}

    @property
    def test_root(self):
        return "/tmp"

    def __init__(self):
        """Constructor for FileSystemProvider."""
        self._namespace = "/"
        self._namespace_id = "/"
        self._cursor = 0
        self._latest_cursor = 0
        self._events = collections.deque([])
        self._evlock = threading.Lock()
        self._evoffset = 0
        self.cache_enabled = True
        self._hash_cache: typing.Dict[str, CacheEnt] = {}
        super().__init__()
        self._test_creds = {"key": "val"}

    def connect_impl(self, creds):
        log.debug("connect mock prov creds : %s", creds)

        if not creds:
            raise ex.CloudTokenError()

        self.__in_connect = True
        self._api("connect_impl", creds)
        self.__in_connect = False

        if self.connection_id is None or self.connection_id == "invalid":
            return os.urandom(16).hex()

        return self.connection_id

    def get_quota(self):
        if not self.connected:
            raise ex.CloudDisconnectedError()
        _total, used, free = shutil.disk_usage(self._namespace)
        return {
            "used": used,
            "limit": free,
            "login": "n/a"
        }

    def _api(self, *args, **kwargs):
        return self

    def __enter__(self):
        pass

    def __exit__(self, ty, exception, tb):
        if isinstance(exception, FileNotFoundError):
            raise ex.CloudFileNotFoundError
        if isinstance(exception, FileExistsError):
            raise ex.CloudFileExistsError

    @property  # type: ignore
    def latest_cursor(self):
        return self._latest_cursor

    @property  # type: ignore
    def current_cursor(self):
        return self._cursor

    @current_cursor.setter  # type: ignore
    def current_cursor(self, val):
        if val is None:
            val = self.latest_cursor
        if not isinstance(val, int) and val is not None:
            raise ex.CloudCursorError(val)
        self._cursor = val

    def events(self) -> typing.Generator[Event, None, None]:
        while self._cursor < self._latest_cursor:
            pe = None
            with self._evlock:
                if self._cursor < self._latest_cursor:
                    self._cursor += 1
                    pe = self._events[self._cursor - self._evoffset]
            if pe is not None:
                yield pe

    def _oid_to_path(self, oid):
        return self.join(self._namespace_id, oid)

    def _path_to_oid(self, path):
        path = self.normalize_path(path)
        subs = self.is_subpath(self._namespace_id, path)
        if subs[0] != '/':
            subs = '/' + subs
        return subs

    def upload(self, oid, file_like, metadata=None) -> OInfo:
        with self._api():
            path = self._oid_to_path(oid)
            if not os.path.exists(path):
                raise ex.CloudFileNotFoundError(oid)
            with open(path, "wb") as f:
                shutil.copyfileobj(file_like, f)
            return self.info_oid(oid)

    def _fast_hash(self, path):
        if not self.cache_enabled:
            with open(path, "r") as f:
                return get_hash(f)

        path = self.normalize_path(path)

        if path not in self._hash_cache:
            self._hash_cache[path] = CacheEnt()

        st = os.stat(path)
        ci = self._hash_cache[path]
        with open(path, "r") as f:
            first = f.read(1024)
            f.seek(os.SEEK_END, -1024)
            last = f.read(1024)
            qhash = get_hash(first + last)

            # only update hash if modification time changes or if prefix bytes change
            # this can be disabled
            if ci.mtime == 0 or st.st_mtime != ci.mtime or qhash != ci.qhash:
                f.seek(0, 0)
                ci.fhash = get_hash(f)
                ci.qhash = qhash
                ci.mtime = st.st_mtime

        return ci.fhash

    def listdir(self, oid) -> typing.Generator[DirInfo, None, None]:
        with self._api():
            path = self._oid_to_path(oid)
            if not os.path.exists(path):
                raise ex.CloudFileNotFoundError(oid)
            with os.scandir(path) as it:
                for entry in it:
                    path = entry.path
                    ohash = self._fast_hash(path)
                    otype = OType.DIRECTORY if entry.is_dir() else OType.FILE
                    yield DirInfo(otype=otype, oid=oid, hash=ohash, path=path)

    def create(self, path, file_like, metadata=None) -> OInfo:
        with self._api():
            with open(path, "wb") as dest:
                shutil.copyfileobj(file_like, dest)
                return self.info_path(path)

    def download(self, oid, file_like):
        with self._api():
            path = self._oid_to_path(oid)
            with open(path, "rb") as src:
                shutil.copyfileobj(src, file_like)

    def rename(self, oid, path) -> str:
        with self._api():
            path_from = self._oid_to_path(oid)
            os.rename(path_from, path)
            return self._path_to_oid(path)

    def mkdir(self, path) -> str:
        with self._api():
            os.mkdir(path)
            return self._path_to_oid(path)

    def delete(self, oid):
        with self._api():
            path = self._oid_to_path(oid)
            os.unlink(path)

    def exists_oid(self, oid):
        with self._api():
            path = self._oid_to_path(oid)
            return os.path.exists(path)

    def exists_path(self, path) -> bool:
        with self._api():
            return os.path.exists(path)

    def hash_oid(self, oid) -> bytes:
        with self._api():
            path = self._oid_to_path(oid)
            return self._fast_hash(path)

    def hash_data(self, file_like) -> bytes:
        return self._fast_hash(file_like)

    def info_path(self, path: str, use_cache=True) -> typing.Optional[OInfo]:
        if not os.path.exists(path):
            return None
        isdir = os.path.isdir(path)

        fhash = None if isdir else self._fast_hash(path)
        otype = OType.DIRECTORY if isdir else OType.FILE
        oid = self._path_to_oid(path)
        path = canonicalize_fpath(self.case_sensitive, path)
        return OInfo(otype=otype, oid=oid, hash=fhash, path=path)

    def info_oid(self, oid: str, use_cache=True) -> typing.Optional[OInfo]:
        path = self._oid_to_path(oid)
        return self.info_path(path)


register_provider(FileSystemProvider)
__cloudsync__ = FileSystemProvider
