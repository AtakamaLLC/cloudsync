import os
import copy
import requests
import logging
from typing import Optional, Generator, TYPE_CHECKING
from unittest.mock import patch

from cloudsync.tests.fixtures import Provider
from cloudsync.runnable import time_helper
from .retry_wrapper import wrap_retry, EXPECTED_EXCEPTIONS
from cloudsync import (
    Event,
    CloudFileNotFoundError,
    CloudTemporaryError,
    CloudFileExistsError,
    CloudTokenError,
)
from cloudsync.types import OInfo

log = logging.getLogger(__name__)

# this is, apparently, the only way to deal with mixins, see: https://github.com/python/mypy/issues/5837
if TYPE_CHECKING:
    # we know that the providerhelper will always be mixed in with a provider
    ProviderBase = Provider
else:
    # but we can't actually derive from it or stuff will break
    ProviderBase = object


class ProviderTestMixin(ProviderBase):
    """Mixin class that supports testing providers.

    Features:
        - automatic retry and reconnect from CloudTemporaryError and CloudDisconnectedError
        - use of test_ exports for timeouts, CI creds, etc.
        - automatic root for tests inside a test folder, with automatic translation
    """

    def __init__(self, prov, connect=True, short_poll_only=True, isolation_string=None):
        # if you plan on patching _api you must use a scoped_provider!!!

        self.api_retry = True
        self.prov = prov

        self.test_parent = getattr(self.prov, "test_root", "/")
        self._test_event_timeout = getattr(self.prov, "_test_event_timeout", 20)
        self._test_event_sleep = getattr(self.prov, "_test_event_sleep", 1)
        self._test_creds = getattr(self.prov, "_test_creds", {})
        if not isolation_string:
            isolation_string = os.urandom(16).hex()
        self.test_root: str = self.join(self.test_parent, isolation_string)

        self.prov_api_func = self.prov._api
        self.prov._api = lambda *ar, **kw: self.__api_retry(self._api, *ar, **kw)

        self.__short_poll_only = short_poll_only
        prov.test_short_poll_only(short_poll_only=short_poll_only)

        self.__patches = []

        # ensure requests lib is used correctly
        old_send = requests.Session.send

        def new_send(*args, **kwargs):
            if not kwargs.get("timeout", None):
                log.error("requests called without timout", stack_info=True)
                assert False
            return old_send(*args, **kwargs)

        p = patch.object(requests.Session, "send", new_send)
        p.start()
        self.__patches.append(p)

        if connect:
            try:
                self.prov.connect(self._test_creds)
            except CloudTokenError:
                prov.connection_id = None
                self.prov.connect(self._test_creds)
            assert prov.connection_id
            self.make_root()
        else:
            self.prov.disconnect()

    @wrap_retry
    def _raw_mkdir(self, path):
        return self.prov.mkdir(path)

    def make_root(self):
        ns = self.prov.list_ns()
        if ns and hasattr(self.prov, "_test_namespace"):
            self.prov.namespace = self.prov._test_namespace

        log.debug("mkdir test_root %s", self.test_root)
        self._raw_mkdir(self.test_root)

    def _api(self, *ar, **kw):
        return self.prov_api_func(*ar, **kw)

    def __api_retry(self, func, *ar, **kw):
        # the cloud providers themselves should *not* have their own backoff logic
        # rather, they should punt rate limit and temp errors to the sync system
        # since we're not testing the sync system here, we need to make our own
        if not self.api_retry:
            return func(*ar, **kw)

        ex = None
        try:
            for _ in time_helper(timeout=self._test_event_timeout, sleep=self._test_event_sleep):
                try:
                    return func(*ar, **kw)
                except CloudTemporaryError as e:
                    if type(e) in EXPECTED_EXCEPTIONS:
                        log.info("api won't retry: exception was expected %s %s %s: %s", func, ar, kw, repr(e))
                        raise
                    log.info("api retry %s %s %s", func, ar, kw)
                    ex = e
        except TimeoutError as e:
            raise ex or e

    # TEST-ROOT WRAPPER

    @wrap_retry
    def __getattr__(self, k):
        return getattr(self.prov, k)

    def events(self) -> Generator[Event, None, None]:
        for e in self.prov.events():
            if self.__filter_root(e) or not e.exists:
                yield self.__strip_root(e)

    def walk(self, path, recursive=True):
        path = self.__add_root(path)
        log.debug("TEST WALK %s", path)
        for e in self.prov.walk(path, recursive=recursive):
            if self.__filter_root(e):
                yield self.__strip_root(e)

    @wrap_retry
    def download(self, *args, **kwargs):
        return self.__strip_root(self.prov.download(*args, **kwargs))

    @wrap_retry
    def download_path(self, path: str, *args, **kwargs):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.download_path(path, *args, **kwargs))

    @wrap_retry
    def create(self, path, file_like, metadata=None):
        path = self.__add_root(path)
        log.debug("CREATE %s", path)
        return self.__strip_root(self.prov.create(path, file_like, metadata))

    @wrap_retry
    def upload(self, *args, **kwargs):
        return self.__strip_root(self.prov.upload(*args, **kwargs))

    @wrap_retry
    def rename(self, oid, path):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.rename(oid, path))

    @wrap_retry
    def mkdir(self, path):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.mkdir(path))

    @wrap_retry
    def mkdirs(self, path):
        path = self.__add_root(path)
        return self.prov.mkdirs(path)

    @wrap_retry
    def rmtree(self, *args, **kwargs):
        log.debug("rmtree %s %s", args, kwargs)
        return self.__strip_root(self.prov.rmtree(*args, **kwargs))

    @wrap_retry
    def delete(self, *args, **kwargs):
        log.debug("DELETE %s %s", args, kwargs)
        return self.__strip_root(self.prov.delete(*args, **kwargs))

    @wrap_retry
    def exists_oid(self, oid):
        return self.prov.exists_oid(oid)

    @wrap_retry
    def exists_path(self, path):
        path = self.__add_root(path)
        return self.prov.exists_path(path)

    @wrap_retry
    def info_path(self, path: str, use_cache=True) -> Optional[OInfo]:
        path = self.__add_root(path)
        return self.__strip_root(self.prov.info_path(path, use_cache))

    @wrap_retry
    def set_root(self, root_path: str = None, root_oid: str = None):
        if root_path:
            root_path = self.__add_root(root_path)
        (_, root_oid) = self.prov.set_root(root_path, root_oid)
        root_path = self.info_oid(root_oid).path
        return root_path, root_oid

    @wrap_retry
    def info_oid(self, oid: str, use_cache=True) -> Optional[OInfo]:
        return self.__strip_root(self.prov.info_oid(oid))

    @wrap_retry
    def listdir(self, oid):
        for e in self.prov.listdir(oid):
            if self.__filter_root(e):
                yield self.__strip_root(e)

    @wrap_retry
    def listdir_path(self, path):
        path = self.__add_root(path)
        for e in self.prov.listdir_path(path):
            if self.__filter_root(e):
                yield self.__strip_root(e)

    @wrap_retry
    def listdir_oid(self, oid, path=None):
        path = self.__add_root(path)
        for e in self.prov.listdir_oid(oid, path):
            if self.__filter_root(e):
                yield self.__strip_root(e)

    def __add_root(self, path):
        return self.prov.join(self.test_root, path)

    def __filter_root(self, obj):
        if hasattr(obj, "path"):
            raw_path = obj.path

            if not raw_path:
                info = self.prov.info_oid(obj.oid)
                if info:
                    raw_path = info.path

            if not raw_path:
                # pathless objects always get passed through
                # so isolation is not perfect
                return True

            if not self.prov.is_subpath(self.test_root, raw_path):
                return False

        return True

    def __strip_root(self, obj):
        obj_copy = copy.copy(obj)
        if hasattr(obj_copy, "path") and obj_copy.path:
            relative = self.prov.is_subpath(self.test_root, obj_copy.path)
            if relative:
                # TODO: This does not obey provider control over paths. Frex, consider windows paths and "C:"
                if not relative.startswith(self.prov.sep):
                    relative = self.prov.sep + relative
                obj_copy.path = relative
        return obj_copy

    # HELPERS

    def temp_name(self, name="tmp", *, folder=None):
        # Temp name with some special characters
        fname = self.prov.join(folder or self.prov.sep, os.urandom(16).hex() + "(. # " + name)
        return fname

    def events_poll(self, timeout=None, until=None) -> Generator[Event, None, None]:
        if timeout is None:
            timeout = self._test_event_timeout

        if timeout == 0:
            yield from self.events()
            return

        for _ in time_helper(timeout, sleep=self._test_event_sleep):
            got = False
            for e in self.events():
                yield e
                got = True
            if not until and got:
                break
            if until and until():
                break

    def __cleanup(self, oid):
        try:
            self.rmtree(oid)
        except (CloudFileNotFoundError, CloudFileExistsError):
            # exists error can happen when deleting root oid
            pass
        except Exception as e:
            log.error("error during cleanup %s", repr(e))

    def test_cleanup(self, *, connected, disconnect=True):
        for p in self.__patches:
            p.stop()

        self.prov._root_path = None
        self.prov._root_oid = None

        if not connected:
            return

        if not self.prov.connected:
            self.prov.connect(self._test_creds)
        info = self.prov.info_path(self.test_root)
        if info:
            self.__cleanup(info.oid)
        if disconnect:
            self.prov.disconnect()

    @wrap_retry
    def prime_events(self):
        try:
            self.prov.test_short_poll_only(True)
            for _ in self.events():
                pass
        finally:
            self.prov.test_short_poll_only(self.__short_poll_only)
        self.current_cursor = self.latest_cursor

    @property
    def current_cursor(self):
        return self.prov.current_cursor

    @current_cursor.setter
    def current_cursor(self, val):
        self.prov.current_cursor = val

    @property                           # type: ignore
    def connection_id(self) -> str:     # type: ignore
        return self.prov.connection_id

    @connection_id.setter
    def connection_id(self, val: str):  # type: ignore
        self.prov.connection_id = val

    @property           # type: ignore
    @wrap_retry
    def namespace(self):
        return self.prov.namespace

    @namespace.setter   # type: ignore
    @wrap_retry
    def namespace(self, val):
        self.prov.namespace = val

    @property
    def namespace_id(self):
        return self.prov.namespace_id

    @namespace_id.setter
    def namespace_id(self, val):
        self.prov.namespace_id = val


