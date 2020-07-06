import os
import sys
import glob
import errno
import time
import re
import tempfile
import logging
import pathlib
import shutil
import collections
import threading
from hashlib import blake2b
import typing
from dataclasses import dataclass

from watchdog import events as watchdog_events
from watchdog.observers import Observer as watchdog_observer
# uncomment if you want to determine if issues are caused by platform polling code
# from watchdog.observers.polling import PollingObserver as watchdog_observer

from cloudsync.event import Event
from cloudsync.provider import Provider, Namespace
from cloudsync.registry import register_provider
from cloudsync.types import OInfo, OType, DirInfo
import cloudsync.exceptions as ex


def is_osx():
    return sys.platform == "darwin"


def is_windows():
    return sys.platform == "win32"


if is_windows():
    import win32file  # pylint: disable=import-error

if is_osx():
    from Foundation import NSURL  # pylint: disable=import-error,no-name-in-module

if is_windows():
    import ctypes
    from ctypes import wintypes
    _GetLongPathNameW = ctypes.windll.kernel32.GetLongPathNameW                         # type: ignore
    _GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    _GetLongPathNameW.restype = wintypes.DWORD

    def get_long_path_name(short_name):
        """
        http://stackoverflow.com/a/23598461/200291
        """
        output_buf_size = 0
        while True:
            output_buf = ctypes.create_unicode_buffer(output_buf_size)
            needed = _GetLongPathNameW(short_name, output_buf, output_buf_size)
            if output_buf_size >= needed:
                return output_buf.value
            else:
                output_buf_size = needed
else:
    def get_long_path_name(short_name):
        return short_name

logging.getLogger("watchdog").setLevel(logging.INFO)
log = logging.getLogger(__name__)


def get_hash(dat):
    """Returns a hash of it's argument which can be a bytes or filelike object"""
    # 32-byte blake optimized for 64 bit chips
    if not hasattr(dat, "read"):
        return blake2b(dat, digest_size=32).digest()
    blocksize = 4096
    d = blake2b(digest_size=32)
    block = dat.read(blocksize)
    while block:
        d.update(block)
        block = dat.read(blocksize)
    return d.digest()


def detect_case_sensitive(tmpdir=None):
    """Returns true if temp directory specified is case sensitive, or gettempdir() if unspecified."""
    if not tmpdir:
        tmpdir = tempfile.gettempdir()
    f1 = os.path.join(tmpdir, "tmp." + os.urandom(16).hex().lower())
    try:
        with open(f1, "w") as f:
            f.write("x")
        f2 = f1.upper()
        if os.path.exists(f2):
            return False
    finally:
        if os.path.exists(f1):
            os.unlink(f1)
    return True


def canonicalize_tail_win32(path: str) -> str:
    """Efficient canonicalize tail for windows."""

    p = pathlib.Path(path)
    par = p.parent

    try:
        # Equivalent to FindFirstFileW, the moral equivalent of stat().
        # The file name in the returned struct will have "true" case.
        itr = win32file.FindFilesIterator(path)
        info = next(itr)
        canon_name: str = info[8]
        p = par / canon_name
    except StopIteration:
        # Couldn't find the path component.
        pass
    except Exception as e:
        # something else went wrong, somehow, log exception and swallow
        # likely this is a permission denied
        log.error("Unexpected exception in FindFirstFile: %s", e)

    ret = str(p)

    lname = get_long_path_name(ret)

    ret = lname or ret

    return ret


def canonicalize_tail_existing(path):
    """Fixes the case of the last component of a file to the name on disk.

    Works only if the path exists.
    """
    if is_osx():
        url = NSURL.fileURLWithPath_(path)  # will be None if path doesn't exist
        if not url:
            return path
        return url.fileReferenceURL().path()

    if is_windows():
        return canonicalize_tail_win32(path)

    # todo: make an explicit version of this line noise
    r = glob.glob(re.sub(r'([^:/\\])(?=[/\\]|$)', r'[\1]', path))
    return r[0] if r else path


def canonicalize_tail(case_sensitive: bool, full_path: str) -> str:
    """Fixes the case of the last component of a path.

    If the parent folder doesn't exist, this does nothing.
    """
    if case_sensitive:
        # not needed for case sensitive installations
        return full_path

    if not os.path.exists(full_path):
        # canonicalize function doesn't work if the path doesn't exist
        fdir, fname = os.path.split(full_path)
        cp = canonicalize_tail_existing(fdir)
        fp: str = os.path.join(cp, fname)
    else:
        fp = canonicalize_tail_existing(full_path)  # canonicalizes path to an existing file

    if not fp:
        log.warning("canonicalize doesn't yet support missing parent folders %s", full_path)
        return full_path

    return fp


@dataclass
class CacheEnt:
    mtime = 0.0
    qhash = b''
    fhash = b''


class Observer(watchdog_events.FileSystemEventHandler):
    """One observer of a single path, can have lots of callbacks."""

    def __init__(self, path):
        self.path = path
        self.callbacks = set()
        self.thread = watchdog_observer()
        log.info("start %s for path %s", type(self.thread), path)
        self.thread.schedule(self, path, recursive=True)
        self.thread.start()

        self.prev_event_type: type = None
        self.prev_event_src: str = None
        self.prev_event_dest: str = None
        self.prev_event_time: float = None

    def add(self, callback):
        self.callbacks.add(callback)

    def discard(self, callback):
        self.callbacks.discard(callback)

    def stop(self):
        log.debug("stop observer %s", self.path)
        self.thread.stop()

    def empty(self):
        return not self.callbacks

    def on_any_event(self, event):
        """Called by watchdog on fs events."""

        # filter out lots of the same events in the same millisecond
        if (type(event) == self.prev_event_type and
                event.src_path == self.prev_event_src and
                getattr(event, "dest_path", None) == self.prev_event_dest and
                time.monotonic() < self.prev_event_time + 0.01):
            return

        self.prev_event_type = type(event)
        self.prev_event_src = event.src_path
        self.prev_event_dest = getattr(event, "dest_path", None)
        self.prev_event_time = time.monotonic()

# uncomment for too-heavy debugging
#        log.debug("raw event %s %s", id(self), event)
        for cb in self.callbacks:
            try:
                cb(event)
            except Exception:
                log.exception("error processing event")


class ObserverPool:
    """Watchdog seems to have issues with start/stop on Windows.

    Creating a pool of watchers resolves this,
    """

    def __init__(self, case_sensitive):
        self.pool = {}
        self.case_sensitive = case_sensitive

    def generic_normalize_path(self, path):
        path = path.replace("\\", "/")
        if self.case_sensitive:
            path = path.lower()
        return path

    def add(self, path, callback):
        # fixes inotify limit errors on linux
        if path == "/":
            return

        npath = self.generic_normalize_path(path)
        if npath not in self.pool:
            self.pool[npath] = Observer(path)
        log.debug("add observer %s", callback)
        self.pool[npath].add(callback)

    def discard(self, path, callback):
        """Remove a callback.

        If path is None, removes all callbacks matching
        """
        if path is None:
            for sub in list(self.pool):
                self.discard(sub, callback)
            return
        npath = self.generic_normalize_path(path)
        if npath not in self.pool:
            return
        log.debug("remove observer %s", callback)
        self.pool[npath].discard(callback)

        # we should run this code below, but not right away
        # maybe set an event on a thread that wakes up, sleeps for a few seconds
        # then sees if anything is empty, and stops them
        # the reason is that windows starts to fail if we thrash
        #
        # update: 
        # this resolves test failures due to having too many active observers
        # so far, have not noticed any windows thrashing problems as mentioned above
        if self.pool[npath].empty():
            self.pool[npath].stop()
            log.debug("delete observer for %s", npath)
            del self.pool[npath]


class FileSystemProvider(Provider):                     # pylint: disable=too-many-instance-attributes, too-many-public-methods
    """
    FileSystemProvider is a provider that uses the filesystem, and full paths as the storage location.
    """
    default_sleep = 0.01
    name = "filesystem"
    oid_is_path = True
    case_sensitive = detect_case_sensitive()
    win_paths = is_windows()
    default_sleep = 1
    _max_queue = 10000
    _test_event_timeout = 2
    _test_event_sleep = 0.001
    _test_namespace_path = os.path.join(tempfile.gettempdir(), os.urandom(16).hex())
    _observers = ObserverPool(case_sensitive)
    _additional_invalid_characters = ":" if is_windows() else ""

    def __init__(self):
        """Constructor for FileSystemProvider."""
        self._namespace: typing.Optional[Namespace] = None
        self._cursor = 0
        self._latest_cursor = 0
        self._events: typing.Deque[Event] = collections.deque([])
        self._evlock = threading.Lock()
        self._evoffset = 0
        self._event_window = 1000
        self._rmdirs = []
        self._cache_enabled = True
        self._hash_cache: typing.Dict[str, CacheEnt] = {}
        super().__init__()

    @property
    def namespace(self) -> typing.Optional[Namespace]:
        return self._namespace

    @namespace.setter
    def namespace(self, namespace: Namespace):
        self.namespace_id = namespace.id

    @property
    def namespace_id(self) -> typing.Optional[str]:
        return self._namespace.id if self._namespace else None

    @namespace_id.setter
    def namespace_id(self, path: str):
        if self._namespace and self.paths_match(self._namespace.id, path):
            return
        if not os.path.exists(path):
            os.mkdir(path)
        path = self._fpath_to_oid(get_long_path_name(path))
        log.info("set namespace %s", path)
        self._namespace = Namespace(name=path, id=path)
        self._connect_observer(path)

    def disconnect(self):
        if self._namespace:
            self._observers.discard(self._namespace.id, self._on_any_event)
        super().disconnect()

    def _connect_observer(self, path: str):
        try:
            with self._api():
                self._observers.discard(path=None, callback=self._on_any_event)
                self._observers.add(path, self._on_any_event)
        except OSError:
            log.info("cannot get events for %s", path)

    def connect_impl(self, creds):
        if self._namespace:
            self._connect_observer(self._namespace.id)
        return super().connect_impl(creds)

    def get_quota(self):
        if not self._namespace:
            raise ex.CloudDisconnectedError("namespace not set")
        ret = shutil.disk_usage(self._namespace.id)
        return {
            "used": ret.used,
            "limit": ret.total,
            "login": "n/a"
        }

    def _api(self, *args, **kwargs):
        return self

    # todo: break these out into their own class and make it a required argument for stuff
    # like fast_hash_path and other bad things

    def __enter__(self):
        pass

    def __exit__(self, ty, exception, tb):
        if isinstance(exception, FileNotFoundError):
            raise ex.CloudFileNotFoundError
        if isinstance(exception, FileExistsError):
            raise ex.CloudFileExistsError
        if isinstance(exception, IsADirectoryError):
            raise ex.CloudFileExistsError("Is a dir: %s" % exception)
        if isinstance(exception, NotADirectoryError):
            raise ex.CloudFileExistsError("Not a dir: %s" % exception)
        if isinstance(exception, OSError):
            if exception.errno == errno.ENOTEMPTY:
                raise ex.CloudFileExistsError("Dir not empty: %s" % exception)
            if exception.errno == errno.ENOTDIR:
                raise ex.CloudFileExistsError("Not a dir: %s" % exception)
            if exception.errno == errno.ENOSPC:
                raise ex.CloudOutOfSpaceError("no space: %s" % exception)
            if exception.errno == errno.ENAMETOOLONG:
                raise ex.CloudFileNameError("Invalid name: %s" % exception)
            raise

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
        if val > (self.latest_cursor + 1):
            raise ex.CloudCursorError("%s is not a valid cursor" % val)

        self._cursor = val

    def _convert_watchdog_event(self, event):
        otype = OType.DIRECTORY if event.is_directory else OType.FILE
        fpath = event.src_path
        oid = self._fpath_to_oid(fpath)
        exists = True
        prior_oid = None

        if hasattr(event, "dest_path"):
            prior_oid = oid
            fpath = event.dest_path
            oid = self._fpath_to_oid(fpath)

        if type(event) in (watchdog_events.DirDeletedEvent, watchdog_events.FileDeletedEvent):
            exists = False

        if type(event) in (watchdog_events.DirModifiedEvent, ) and exists:
            return None

        mtime = time.time()
        if exists:
            try:
                stat = os.stat(fpath)
                mtime = stat.st_mtime
            except FileNotFoundError:
                exists = False

        ret = Event(otype=otype, hash=None, path=self._trim_ns(fpath), oid=oid, exists=exists, prior_oid=prior_oid, mtime=mtime)
        return ret

    def _on_any_event(self, event):
        ev = self._convert_watchdog_event(event)
        if not ev:
            return
        with self._evlock:
            self._latest_cursor += 1
            ev.new_cursor = self._latest_cursor
            self._events.append(ev)
            assert self._events[ev.new_cursor - 1] is ev
            assert len(self._events) + self._evoffset == self._latest_cursor

    def events(self) -> typing.Generator[Event, None, None]:
        if self._cursor < self._evoffset:
            self._cursor = self._evoffset

        while self._cursor < self._latest_cursor:
            pe = None
            with self._evlock:
                if self._cursor < self._latest_cursor:
                    pe = self._events[self._cursor - self._evoffset]
                    self._cursor += 1
            if pe is not None:
                yield pe
        while len(self._events) > self._event_window:
            with self._evlock:
                self._events.popleft()
                self._evoffset += 1
        assert len(self._events) + self._evoffset == self._latest_cursor

    @staticmethod
    def _oid_to_fpath(oid):
        return oid

    def _fpath_to_oid(self, path):
        return self.normalize_path(path)

    def upload(self, oid, file_like, metadata=None) -> OInfo:
        with self._api():
            fpath = self._oid_to_fpath(oid)
            if os.path.isdir(fpath):
                raise ex.CloudFileExistsError()
            if not os.path.exists(fpath):
                raise ex.CloudFileNotFoundError(oid)
            tmpdir = tempfile.gettempdir()
            tmp_file = os.path.join(tmpdir, "tmp." + os.urandom(16).hex())
            with open(tmp_file, "wb") as f:
                shutil.copyfileobj(file_like, f)
            try:
                with open(tmp_file, "rb") as src, open(fpath, "wb") as dest:
                    shutil.copyfileobj(src, dest)
            finally:
                try:
                    os.unlink(tmp_file)
                except Exception:
                    log.debug("cannot remove temp %s", tmp_file)
            self._clear_hash_cache(fpath)
            return self.info_oid(oid)

    def _clear_hash_cache(self, path):
        norm_path = self.normalize_path(path)
        self._hash_cache.pop(norm_path, None)

    def _fast_hash_path(self, path):
        if os.path.isdir(path):
            return None

        if not self._cache_enabled:
            with open(path, "rb") as f:
                return get_hash(f)

        norm_path = self.normalize_path(path)
        if norm_path not in self._hash_cache:
            self._hash_cache[norm_path] = CacheEnt()
        ci = self._hash_cache[norm_path]

        st = os.stat(path)
        with open(path, "rb") as f:
            fhash, final = self._fast_hash_data(f)

        # only update hash if modification time changes or if prefix bytes change
        # this can be disabled
        if not ci.qhash or st.st_mtime != ci.mtime or fhash != ci.fhash:
            if final:
                ci.qhash = fhash
            else:
                with open(path, "rb") as f:
                    ci.qhash = get_hash(f)
            ci.fhash = fhash
            ci.mtime = st.st_mtime
        return ci.qhash

    @staticmethod
    def _fast_hash_data(file_like):
        file_like.seek(0, os.SEEK_END)
        length = file_like.tell()
        file_like.seek(0, os.SEEK_SET)
        first = file_like.read(1024)
        if length > 1024:
            last_size = min(1024, length - 1024)
            file_like.seek(0 - last_size, os.SEEK_END)
            last = file_like.read(last_size)
        else:
            last = b''
        # log.debug("first+last = %s", first+last)
        return get_hash(first + last), not last

    def listdir(self, oid) -> typing.Generator[DirInfo, None, None]:
        with self._api():
            fpath = self._oid_to_fpath(oid)
            try:
                with os.scandir(fpath) as it:
                    for entry in it:
                        entry_path = entry.path
                        ohash = self._fast_hash_path(entry_path)
                        otype = OType.DIRECTORY if entry.is_dir() else OType.FILE
                        name = self.is_subpath(fpath, entry_path).lstrip("/")
                        path = self._trim_ns(entry_path)
                        yield DirInfo(otype=otype, oid=self._fpath_to_oid(entry_path), hash=ohash, path=path, name=name)
            except NotADirectoryError:
                raise ex.CloudFileNotFoundError("not a directory")

    def create(self, path, file_like, metadata=None) -> OInfo:
        fpath = self.join(self.namespace_id, path)
        with self._api():
            parent = self.dirname(fpath)
            if os.path.exists(fpath) or (os.path.exists(parent) and not os.path.isdir(parent)):
                raise ex.CloudFileExistsError()
            with open(fpath, "wb") as dest:
                try:
                    shutil.copyfileobj(file_like, dest)
                except Exception:
                    if os.path.exists(fpath):
                        dest.close()
                        os.unlink(fpath)
                    raise
            log.debug("create ok %s", fpath)
            self._clear_hash_cache(fpath)
            return self.__info_path(path, fpath)

    def download(self, oid, file_like):
        with self._api():
            fpath = self._oid_to_fpath(oid)
            with open(fpath, "rb") as src:
                shutil.copyfileobj(src, file_like)

    def rename(self, oid, path) -> str:
        fpath = self.join(self.namespace_id, path)
        with self._api():
            path_from = self._oid_to_fpath(oid)
            if not os.path.exists(path_from):
                raise ex.CloudFileNotFoundError
            parent = self.dirname(fpath)
            if not os.path.exists(parent):
                raise ex.CloudFileNotFoundError(parent)
            if not os.path.isdir(parent):
                raise ex.CloudFileExistsError(fpath)
            if not self.paths_match(path_from, fpath, for_display=True):
                from_dir = os.path.isdir(path_from)
                to_dir = os.path.isdir(fpath)
                has_contents = False
                if os.path.exists(fpath):
                    if to_dir:
                        has_contents = self._folder_path_has_contents(fpath)
                    if (not to_dir or to_dir != from_dir or (to_dir and has_contents)):
                        if not self.paths_match(path_from, fpath):
                            raise ex.CloudFileExistsError(fpath)
                try:
                    assert os.path.exists(path_from)
                    assert os.path.exists(parent)
                    log.info("rename %s -> %s", path_from, fpath)
                    os.rename(path_from, fpath)
                except FileExistsError:
                    if not has_contents and is_windows() and to_dir:
                        # win32 doesn't allow this, so force it
                        tmpname = fpath + os.urandom(16).hex()
                        os.rename(fpath, tmpname)
                        os.rename(path_from, fpath)
                        self._rmdirs.append(tmpname)
                    else:
                        raise

            return self._fpath_to_oid(fpath)

    def mkdir(self, path) -> str:
        fpath = self.join(self.namespace_id, path)
        with self._api():
            parent = self.dirname(fpath)
            if os.path.isfile(parent) or os.path.isfile(fpath):
                raise ex.CloudFileExistsError()
            if not os.path.exists(fpath):
                os.mkdir(fpath)

            return self._fpath_to_oid(fpath)

    def _folder_path_has_contents(self, path):
        oid = self._fpath_to_oid(path)
        if oid:
            return self._folder_oid_has_contents(oid)
        return False

    def _folder_oid_has_contents(self, oid):
        try:
            next(self.listdir(oid))
            return True
        except StopIteration:
            return False

    def delete(self, oid):
        with self._api():
            path = self._oid_to_fpath(oid)
            if os.path.isdir(path):
                log.debug("delete dir %s", path)
                if self._folder_oid_has_contents(oid):
                    raise ex.CloudFileExistsError("Cannot delete non-empty folder %s:%s" % (oid, path))
                os.rmdir(path)
            elif os.path.exists(path):
                log.debug("delete file %s", path)
                os.unlink(path)
            else:
                log.debug("delete ??? %s", path)

    def exists_oid(self, oid):
        with self._api():
            path = self._oid_to_fpath(oid)
            return os.path.exists(path)

    def exists_path(self, path) -> bool:
        path = self.join(self.namespace_id, path)
        with self._api():
            return os.path.exists(path)

    def hash_oid(self, oid) -> bytes:
        with self._api():
            path = self._oid_to_fpath(oid)
            return self._fast_hash_path(path)

    def hash_data(self, file_like) -> bytes:
        with self._api():
            return self._fast_hash_data(file_like)[0]

    def info_path(self, path: str, use_cache=True) -> typing.Optional[OInfo]:
        return self.__info_path(path, None, canonicalize=True)

    def __info_path(self, path: str, fpath: str, canonicalize=False) -> typing.Optional[OInfo]:
        if fpath is None:
            fpath = self.join(self.namespace_id, path)

        if not os.path.exists(fpath):
            return None

        if path is None or canonicalize:
            cpath = canonicalize_tail(self.case_sensitive, fpath)
            if not self.paths_match(cpath, fpath):
                log.debug("canonicalize failure %s != %s", cpath, fpath)
            path = self._trim_ns(cpath)

        with self._api():
            fhash = self._fast_hash_path(fpath)
            otype = OType.DIRECTORY if os.path.isdir(fpath) else OType.FILE
            oid = self._fpath_to_oid(fpath)
            ret = OInfo(otype=otype, oid=oid, hash=fhash, path=path)
            return ret

    def _trim_ns(self, path):
        subs = self.is_subpath(self.namespace_id, path)
        if subs:
            return subs
        log.debug("%s is not within %s", path, self.namespace_id)
        return None

    def info_oid(self, oid: str, use_cache=True) -> typing.Optional[OInfo]:
        fpath = self._oid_to_fpath(oid)
        return self.__info_path(None, fpath)

    def list_ns(self, recursive=True, parent=None):
        return [self._test_namespace]

    @property
    def _test_namespace(self):
        long_path = get_long_path_name(self._test_namespace_path)
        ns = self._fpath_to_oid(long_path) if long_path else self._test_namespace_path
        return Namespace(name=ns, id=ns)


register_provider(FileSystemProvider)
__cloudsync__ = FileSystemProvider
