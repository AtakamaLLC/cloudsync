# pylint: disable=protected-access, too-many-lines

"""Exported provider tests.

This test suite can be imported by using:

```
from cloudsync.tests import *
```

Plugins seeking to implement providers should import these tests to be sure they conform.

Conforming providers should work well with the real-time sync engines.

Under the LGPL, there is no obligation to publish your plugins.
"""

import os
import errno
import logging
import io
from io import BytesIO
from os import SEEK_SET, SEEK_CUR, SEEK_END
import threading
import time
import copy

from typing import Optional, Generator, TYPE_CHECKING, List, cast
from unittest.mock import patch

import requests
import msgpack
import pytest
from _pytest.fixtures import FixtureLookupError

import cloudsync
import cloudsync.providers

from cloudsync import Event, CloudException, CloudFileNotFoundError, CloudDisconnectedError, CloudTemporaryError, CloudFileExistsError, \
        CloudOutOfSpaceError, CloudCursorError, CloudTokenError, CloudNamespaceError
from cloudsync.provider import Namespace
from cloudsync.tests.fixtures import Provider, MockProvider
from cloudsync.runnable import time_helper
from cloudsync.types import OInfo


# pylint: disable=missing-docstring

log = logging.getLogger(__name__)

# this is, apparently, the only way to deal with mixins, see: https://github.com/python/mypy/issues/5837
if TYPE_CHECKING:
    # we know that the providerhelper will always be mixed in with a provider
    ProviderBase = Provider
else:
    # but we can't actually derive from it or stuff will break
    ProviderBase = object


def wrap_retry(func):                 # pylint: disable=too-few-public-methods
    count = 4

    def wrapped(prov, *args, **kwargs):
        ex: CloudException = None
        mult = 1.0
        for i in range(count):
            if i > 0:
                log.warning("retry %s after %s", func.__name__, repr(ex))
            try:
                return func(prov, *args, **kwargs)
            except CloudTemporaryError as e:
                ex = e
            except CloudDisconnectedError as e:
                prov.reconnect()
                ex = e
            time.sleep(mult * (prov._test_event_timeout / 5))
            mult = mult * 1.4
        raise ex
    return wrapped


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
    def info_oid(self, oid: str, use_cache=True) -> Optional[OInfo]:
        return self.__strip_root(self.prov.info_oid(oid))

    @wrap_retry
    def listdir(self, oid):
        for e in self.prov.listdir(oid):
            if self.__filter_root(e):
                yield e

    @wrap_retry
    def listdir_path(self, path):
        path = self.__add_root(path)
        for e in self.prov.listdir_path(path):
            if self.__filter_root(e):
                yield e

    @wrap_retry
    def listdir_oid(self, oid, path=None):
        path = self.__add_root(path)
        for e in self.prov.listdir_oid(oid, path):
            if self.__filter_root(e):
                yield e

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

            self.__strip_root(obj)

        return True

    def __strip_root(self, obj):
        if hasattr(obj, "path"):
            path = obj.path
            if path:
                obj = copy.copy(obj)
                relative = self.prov.is_subpath(self.test_root, path)
                if not relative:
                    # event from prior test
                    return obj
                path = relative
                # TODO: This does not obey provider control over paths. Frex, consider windows paths and "C:"
                if not path.startswith(self.prov.sep):
                    path = self.prov.sep + path
                obj.path = path
        return obj
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

    def test_cleanup(self, *, connected):
        for p in self.__patches:
            p.stop()

        if not connected:
            return

        if not self.prov.connected:
            self.prov.connect(self._test_creds)
        self.prime_events()
        info = self.prov.info_path(self.test_root)
        if info:
            self.__cleanup(info.oid)

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


def mixin_provider(prov, connect=True, short_poll_only=True):
    assert prov
    if isinstance(prov, Generator):
        prov = next(prov)
    if not isinstance(prov, List):
        prov = [prov]
    for curr_prov in prov:
        assert isinstance(curr_prov, Provider)
    instances = len(prov)

    isolation_string = None
    if instances > 1:
        isolation_string = os.urandom(16).hex()

    providers = []
    for i in range(instances):
        providers.append(ProviderTestMixin(prov[i], connect=connect, short_poll_only=short_poll_only, isolation_string=isolation_string))  # type: ignore
    if len(providers) == 1:
        yield providers[0]
    else:
        yield providers

    for curr_prov in providers:
        curr_prov.test_cleanup(connected=connect)


@pytest.fixture
def provider_params():
    return None


def config_provider_impl(request, provider_name, instances):
    provs = list()
    for i in range(instances):
        try:
            provs.append(request.getfixturevalue("cloudsync_provider"))
        except FixtureLookupError:
            if provider_name == "external":
                raise
            provs.append(cloudsync.registry.get_provider(provider_name).test_instance())
    if len(provs) == 1:
        provs = provs[0]
    yield provs


@pytest.fixture(name="config_provider", scope="module")
def config_provider_fixture(request, provider_name, instances=1):
    yield from config_provider_impl(request, provider_name, instances)


@pytest.fixture(scope="module")
def two_config_providers(request, provider_name, instances=2):
    yield from config_provider_impl(request, provider_name, instances)


@pytest.fixture(name="provider")
def provider_fixture(config_provider):
    yield from mixin_provider(config_provider)


# === function scoped, less efficient, good for connect/disconnect tests

@pytest.fixture(name="unwrapped_provider")
def unwrapped_provider_fixture(request, provider_name, instances=1):
    yield from config_provider_impl(request, provider_name, instances)


@pytest.fixture(name="unconnected_provider")
def provider_fixture_unconnected(config_provider):
    yield from mixin_provider(config_provider, connect=False)


@pytest.fixture(name="scoped_provider")
def scoped_provider_fixture(config_provider):
    yield from mixin_provider(config_provider)


@pytest.fixture(name="very_scoped_provider")
def very_scoped_provider_fixture(request, provider_name):
    yield from mixin_provider(config_provider_impl(request, provider_name, instances=1))


@pytest.fixture(name="two_scoped_providers")
def two_scoped_provider_fixture(request, provider_name):
    yield from mixin_provider(config_provider_impl(request, provider_name, instances=2))


# must be scoped because makes non-patched modification to provider
@pytest.fixture(name="long_poll_provider")
def scoped_provider_fixture_short_poll(config_provider):
    yield from mixin_provider(config_provider, short_poll_only=False)


_registered = False


def pytest_generate_tests(metafunc):
    global _registered
    if not _registered:
        # prevent xdist bugs!
        # https://stackoverflow.com/questions/25975038/py-test-with-xdist-skipping-all-the-tests-with-n-1
        # xdist requires parameters in order
        for known_prov in sorted(cloudsync.registry.known_providers()):
            metafunc.config.addinivalue_line(
                "markers", known_prov
            )
        _registered = True
        print("Known providers: ", cloudsync.registry.known_providers())

    if "provider_name" in metafunc.fixturenames:
        provs: List[str] = []

        for e in metafunc.config.getoption("provider", []):
            for n in e.split(","):
                n = n.strip()
                if n:
                    provs += [n]

        for e in os.environ.get("CLOUDSYNC_TEST_PROVIDER", "").split(','):
            e = e.strip()
            if e:
                provs += [e]

        kw = metafunc.config.getoption("keyword", "")
        if not provs and kw == "external":
            provs += ["external"]

        if not provs and kw in sorted(cloudsync.registry.known_providers()):
            provs += [kw]

        if not provs:
            for mark in metafunc.definition.own_markers:
                if mark.name == "providers":
                    provs = mark.args[0]
                    break

        if not provs:
            provs = ["mock_oid_ci", "mock_path_cs"]

        marks = [pytest.param(p, marks=[getattr(pytest.mark, p)]) for p in provs]

        metafunc.parametrize("provider_name", marks, scope="module")


def test_join(mock_provider):
    assert "/a/b/c" == mock_provider.join("a", "b", "c")
    assert "/a/c" == mock_provider.join("a", None, "c")
    assert "/a/b/c" == mock_provider.join("/a", "/b", "/c")
    assert "/a/b/c" == mock_provider.join("/a", "\\b", "\\c")
    assert "/a/b/c" == mock_provider.join("\\a", "\\b\\c")
    assert "/a/c" == mock_provider.join("a", "/", "c")


def test_connect_basic(scoped_provider):
    provider = scoped_provider

    assert provider.connected
    provider.disconnect()
    assert not provider.connected
    log.info("recon")
    provider.reconnect()
    assert provider.connected
    assert provider.connection_id
    if provider.connection_id != cloudsync.CONNECTION_NOT_NEEDED:
        provider.disconnect()
        provider.connection_id = "invalid"
        log.info("reset %s == %s", provider, provider.connection_id)
        with pytest.raises(CloudTokenError):
            provider.reconnect()
        assert not provider.connected
        provider.connection_id = None
        provider.reconnect()

        provider.disconnect()
        try:
            provider.get_quota()
            assert False
        except CloudDisconnectedError:
            pass
        provider.reconnect()


def test_info_root(provider):
    info = provider.info_path("/")

    assert info
    assert info.oid
    assert info.path == "/"


def test_create_upload_download(provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")

    try:
        provider.download_path(dest, BytesIO())
        assert False
    except CloudFileNotFoundError:
        pass

    info1 = provider.create(dest, data())

    info2 = provider.upload(info1.oid, data())

    assert info1.hash
    assert info2.hash

    # hash stuff must be jsonable... it can be complex, but must be comparable
    assert msgpack.loads(msgpack.dumps(info1.hash, use_bin_type=True), use_list=False, raw=False) == info1.hash

    assert info1.oid == info2.oid
    assert info1.hash == info2.hash
    assert info1.hash == provider.hash_data(data())

    assert provider.exists_path(dest)

    dest = BytesIO()
    provider.download(info2.oid, dest)

    dest.seek(0)
    assert dest.getvalue() == dat

def test_namespace(provider):
    ns = provider.list_ns()
    if not ns:
        assert not provider.namespace_id
        assert not provider.namespace
        with pytest.raises(CloudNamespaceError):
            provider.namespace_id = "id"
        with pytest.raises(CloudNamespaceError):
            provider.namespace = Namespace("name", "space")
        return

    saved = provider.namespace_id
    assert provider.namespace.id == saved
    if type(provider.namespace) is Namespace:
        assert not provider.namespace.is_parent
        assert not provider.namespace.shared_paths

    try:
        provider.namespace_id = ns[0].id
        assert provider.namespace_id == ns[0].id

        if len(ns) > 1:
            provider.namespace_id = ns[1].id
            log.info("test recon persist %s", ns[1].id)
            provider.disconnect()
            provider.reconnect()
            log.info("namespace is %s", provider.namespace_id)
            assert provider.namespace_id == ns[1].id
        else:
            log.info("not test recon persist")
    finally:
        provider.namespace_id = saved


def test_rename(provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")
    info1 = provider.create(dest, data())
    dest2 = provider.temp_name("dest2")
    provider.rename(info1.oid, dest2)
    assert provider.exists_path(dest2)
    assert not provider.exists_path(dest)

    # test that renaming a folder renames the children
    folder_name1 = provider.temp_name()
    folder_name2 = provider.temp_name()
    file_name = os.urandom(16).hex()
    file_path1 = provider.join(folder_name1, file_name)
    file_path2 = provider.join(folder_name2, file_name)
    sub_folder_name = os.urandom(16).hex()
    sub_folder_path1 = provider.join(folder_name1, sub_folder_name)
    sub_folder_path2 = provider.join(folder_name2, sub_folder_name)
    sub_file_name = os.urandom(16).hex()
    sub_file_path1 = provider.join(sub_folder_path1, sub_file_name)
    sub_file_path2 = provider.join(sub_folder_path2, sub_file_name)

    folder_oid = provider.mkdir(folder_name1)
    sub_folder_oid = provider.mkdir(sub_folder_path1)
    file_info = provider.create(file_path1, data())
    sub_file_info = provider.create(sub_file_path1, data())

    assert provider.exists_path(file_path1)
    assert not provider.exists_path(file_path2)
    assert provider.exists_path(sub_file_path1)
    assert not provider.exists_path(sub_file_path2)
    assert provider.exists_oid(file_info.oid)
    assert provider.exists_oid(sub_file_info.oid)

    new_oid = provider.rename(folder_oid, folder_name2)

    assert provider.exists_path(file_path2)
    assert not provider.exists_path(file_path1)
    assert provider.exists_path(sub_file_path2)
    assert not provider.exists_path(sub_file_path1)
    assert provider.exists_oid(new_oid)

    if not provider.oid_is_path:
        assert provider.exists_oid(file_info.oid)
        assert provider.exists_oid(sub_file_info.oid)
        assert provider.info_oid(file_info.oid).path == file_path2
        assert provider.info_oid(sub_file_info.oid).path == sub_file_path2
    else:
        assert not provider.exists_oid(file_info.oid)
        assert not provider.exists_oid(sub_file_info.oid)

    # move to sub
    dest = provider.temp_name("movy")
    sub_file_name = os.urandom(16).hex()
    sub_file_path3 = provider.join(sub_folder_path2, sub_file_name)
    info1 = provider.create(dest, data())
    new_oid = provider.rename(info1.oid, sub_file_path3)

    # dup rename file
    provider.rename(new_oid, sub_file_path3)

    # dup rename folder
    sfp2 = provider.info_path(sub_folder_path2)
    provider.rename(sfp2.oid, sub_folder_path2)
    log.debug("finished rename test")


def test_mkdir(provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)
    dest = provider.temp_name("dest")
    o1 = provider.mkdir(dest)
    o2 = provider.mkdir(dest)
    assert o1 == o2
    info = provider.info_path(dest)
    assert info.otype == cloudsync.DIRECTORY
    sub_f = provider.temp_name("dest", folder=dest)
    log.debug("parent = %s, sub = %s", dest, sub_f)
    with pytest.raises(CloudFileExistsError):
        provider.create(dest, data(), None)
    assert provider.exists_path(dest)
    log.debug("folder %s exists", dest)
    provider.create(sub_f, data(), None)


def test_rmtree(provider):
    root = "/testroot"
    root_oid = provider.mkdir(root)
    for i in range(2):
        provider.mkdir(provider.join(root, str(i)))
        for j in range(2):
            provider.create(provider.join(root, str(i), str(j)), BytesIO(os.urandom(32)), None)
    provider.rmtree(root_oid)
    assert not provider.exists_oid(root_oid)
    assert not provider.exists_path(root)
    for i in range(2):
        assert not provider.exists_path(provider.join(root, str(i)))
        for j in range(2):
            assert not provider.exists_path(provider.join(root, str(i), str(j)))

    provider.rmtree(root_oid)

    new_file_name = provider.temp_name()
    new_file_info = provider.create(new_file_name, BytesIO(os.urandom(32)))
    provider.rmtree(new_file_info.oid)


def test_walk(scoped_provider):
    provider = scoped_provider
    temp = BytesIO(os.urandom(32))
    folder = provider.temp_name("folder")
    try:
        list(provider.walk(folder))
        assert False
    except CloudFileNotFoundError:
        pass
    provider.mkdir(folder)
    subfolder = provider.join(folder, provider.temp_name("subfolder"))
    provider.mkdir(subfolder)
    dest0 = provider.temp_name("dest0")
    dest1 = provider.join(folder, provider.temp_name("dest1"))
    dest2 = provider.join(subfolder, provider.temp_name("dest2"))
    oids = {}
    info = provider.create(dest0, temp, None)
    oids[dest0] = info.oid
    info = provider.create(dest1, temp, None)
    oids[dest1] = info.oid
    info = provider.create(dest2, temp, None)
    oids[dest2] = info.oid

    got_event = False
    found = {}
    for e in provider.walk("/"):
        if e.otype == cloudsync.DIRECTORY:
            continue
        log.debug("WALK %s", e)
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert oids[path] == e.oid
        found[path] = True
        assert e.mtime
        assert e.exists
        got_event = True

    for x in [dest0, dest1, dest2]:
        assert found.get(x, False) is True
        log.debug("found %s", x)

    assert got_event

    # check non-rec
    found = {}
    for e in provider.walk("/", recursive=False):
        if e.otype == cloudsync.DIRECTORY:
            continue
        log.debug("WALK %s", e)
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert oids[path] == e.oid
        found[path] = True

    for x in [dest0]:
        log.debug("found %s", x)
        assert found.get(x, False) is True

    for x in [dest1, dest2]:
        log.debug("found %s", x)
        assert found.get(x, False) is False

    # check bad oid
    with pytest.raises(CloudFileNotFoundError):
        list(provider.walk_oid("bad-oid"))


def check_event_path(event: Event, provider, target_path):
    # confirms that the path in the event matches the target_path
    # if the provider doesn't provide the path in the event, look it up by the oid in the event
    # if we can't get the path, that's OK if the file doesn't exist
    event_path = event.path
    if event_path is None:
        try:
            event_path = provider.info_oid(event.oid).path
            assert event_path == target_path
        except CloudFileNotFoundError:
            if event.exists:
                raise


# event tests use "prime events" to discard unrelated events, and ensure that the cursor is "ready"
def test_event_basic(provider):
    if provider.prov.name == 'gdrive':
        # TODO: fix this, why is gdrive unreliable at event delivery?
        pytest.xfail("gdrive is flaky")

    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    dest2 = provider.temp_name("dest2")

    provider.prime_events()

    log.debug("create events")
    info1 = provider.create(dest, temp, None)
    info2 = provider.mkdir(dest2)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    received_event2 = None
    event_count1 = 0
    event_count2 = 0
    done = False

    log.debug("waiting for %s and %s", dest, dest2)
    for e in provider.events_poll(until=lambda: done):
        log.debug("got event %s", e)
        # you might get events for the root folder here or other setup stuff
        if e.exists:
            if not e.path:
                info = provider.info_oid(e.oid)
                if info:
                    e.path = info.path

            if e.path == dest:
                received_event = e
                event_count1 += 1

            if e.path == dest2:
                received_event2 = e
                event_count2 += 1

            done = event_count1 > 0 and event_count2 > 0

            event = threading.Event()

            def deadlocker(event):
                # this hits the api in another thread
                list(provider.listdir(info2))
                event.set()

            # make sure nobody holds an rlock during event yields
            threading.Thread(target=deadlocker, daemon=True, args=(event,)).start()

            # this will fail if there's a deadlock
            assert event.wait(timeout=provider.default_sleep)

    assert done
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        path = provider.info_oid(received_event.oid).path
    assert path == dest
    assert received_event.mtime
    assert received_event.exists
    deleted_oid = received_event.oid
    deleted_oid2 = received_event2.oid
    path2 = provider.info_oid(received_event2.oid).path

    assert path2

    log.debug("delete event")

    provider.delete(oid=deleted_oid)
    provider.delete(oid=deleted_oid)  # Tests that deleting a non-existing file does not raise a FNFE
    provider.delete(oid=deleted_oid2)  # Tests that deleting a non-existing file does not raise a FNFE

    received_event = None
    received_event2 = None
    for e in provider.events_poll(until=lambda: received_event is not None and received_event2 is not None):
        log.debug("event-before %s", e)
        if e.exists and e.path is None:
            info2 = provider.info_oid(e.oid)
            if info2:
                e.path = info2.path
            else:
                e.exists = False
            # assert not e.exists or e.path is not None  # This is actually OK, google will do this legitimately

        assert e.otype is not None

        log.debug("event-after %s", e)
        if (not e.exists and e.oid == deleted_oid) or (e.path and path in e.path):
            received_event = e
        if (not e.exists and e.oid == deleted_oid2) or (e.path and path2 in e.path):
            received_event2 = e

    assert received_event is not None
    assert received_event2 is not None
    assert received_event.oid
    assert not received_event.exists
    if received_event.path is not None:
        # assert that the basename of the path and dest are the same
        assert provider.split(received_event.path)[1] == provider.split(dest)[1]
    assert received_event.oid == deleted_oid
    assert received_event.mtime


def test_event_del_create(provider):
    if provider.prov.name == 'box':
        dnll = logging.getLogger('boxsdk.network.default_network').getEffectiveLevel()
        cpll = logging.getLogger('urllib3.connectionpool').getEffectiveLevel()
        logging.getLogger('boxsdk.network.default_network').setLevel(logging.INFO)
        logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG)

    if provider.prov.name == 'gdrive':
        # TODO: fix this, why is gdrive unreliable at event delivery?
        pytest.xfail("gdrive is flaky")

    temp = BytesIO(os.urandom(32))
    temp2 = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    dest2 = provider.temp_name("dest2")

    provider.prime_events()

    info1 = provider.create(dest, temp)
    provider.delete(info1.oid)
    info2 = provider.create(dest, temp2)
    infox = provider.create(dest2, temp2)
    time.sleep(1)

    log.info("test oid 1 %s", info1.oid)
    log.info("test oid 2 %s", info2.oid)
    events = []
    for event in provider.events():
        log.info("test event %s", event)
        # you might get events for the root folder here or other setup stuff
        path = event.path
        if not event.path:
            info = provider.info_oid(event.oid)
            if info:
                path = info.path

        # always possible to get events for other things
        if path == dest or path == dest2 or event.oid in (info1.oid, info2.oid, infox.oid):
            events.append(event)

    event_num = 0
    create1, delete1, create2 = [None] * 3
    for event in events:
        event_num += 1
        if event.exists:
            if event.oid == info1.oid and (not provider.oid_is_path or create1 is None):
                create1 = event_num
                log.info("create1 = %s", event_num)
            if event.oid == info2.oid or (provider.oid_is_path and event.oid == info1.oid and create1 is not None):
                create2 = event_num
                log.info("create2 = %s", event_num)
        else:
            if event.oid == info1.oid:
                delete1 = event_num
                log.info("delete1 = %s", event_num)

    assert len(events), "Event loop timed out before getting any events"

    # if we only got 1 create event for info1, it is most likely for the 2nd create
    if provider.oid_is_path and create1 == create2:
        assert not delete1
        create1 = None

    if create1 is not None:
        assert delete1 is not None  # make sure we got delete1 if we got create1
    assert create2  # we definitely have to see the second create

    if provider.oid_is_path:  # ordering is important for oid_is_path, so these are ordering tests
        # The provider may compress out create1, or compress out the create1 and delete1, or deliver both
        # So, if we saw create1, make sure we got delete1 and that it came after create1
        # If we didn't see create1, it doesn't matter if we saw delete1.
        if create1 is not None:
            assert delete1 is not None
            assert create1 < delete1

        # If we got delete1, it needs to come before create2
        if delete1 is not None:
            assert delete1 < create2
    if provider.prov.name == 'box':
        logging.getLogger('boxsdk.network.default_network').setLevel(dnll)
        logging.getLogger('urllib3.connectionpool').setLevel(cpll)


def test_event_rename(provider):
    if provider.prov.name == 'gdrive':
        # TODO: fix this, why is gdrive unreliable at event delivery?
        pytest.xfail("gdrive is flaky")

    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    dest2 = provider.temp_name("dest2")
    dest3 = provider.temp_name("dest3")

    provider.prime_events()

    info1 = provider.create(dest, temp)
    oid2 = provider.rename(info1.oid, dest2)
    if provider.oid_is_path:
        info1.oid = provider.info_path(dest2).oid
    oid3 = provider.rename(info1.oid, dest3)
    if provider.oid_is_path:
        info1.oid = provider.info_path(dest3).oid

    seen = set()
    last_event = None
    second_to_last = None
    deleted_oid2 = True
    done = False
    for e in provider.events_poll(provider._test_event_timeout * 2, until=lambda: done):
        if provider.oid_is_path:
            assert e.path
        log.debug("event %s", e)
        # you might get events for the root folder here or other setup stuff
        path = e.path
        if not e.path:
            info = provider.info_oid(e.oid)
            if info:
                path = info.path

        last_event = e
        seen.add(e.oid)

        if provider.oid_is_path:
            # 2 and 3 are in order
            if path == dest2:
                if e.exists == False:
                    deleted_oid2 = True
                second_to_last = True
            if path == dest3 and (second_to_last or not provider.oid_is_path):
                done = True
        else:
            done = info1.oid in seen

    if provider.oid_is_path:
        # providers with path based oids need to send intermediate renames accurately and in order
        assert len(seen) > 2
        assert last_event.path == dest3
        assert last_event.prior_oid == oid2 or deleted_oid2
    else:
        # oid based providers just need to let us know something happend to that oid
        assert info1.oid in seen


def test_event_longpoll(long_poll_provider):
    provider = long_poll_provider
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    if provider.prov.name == 'gdrive':
        # TODO: fix this, why is gdrive unreliable at event delivery?
        pytest.xfail("gdrive is flaky")

    provider.prime_events()

    received_event = None

    def waiter():
        nonlocal received_event
        timeout = time.monotonic() + provider._test_event_timeout
        while time.monotonic() < timeout:
            for e in provider.events_poll(until=lambda: received_event):
                if e.exists:
                    if not e.path:
                        info = provider.info_oid(e.oid)
                        if info:
                            e.path = info.path

                    if e.path == dest:
                        received_event = e
                        return

    t = threading.Thread(target=waiter)
    t.start()

    saved_oid = provider.create(dest, temp, None)
    log.debug("create file %s oid=%s", dest, saved_oid)

    t.join(timeout=provider._test_event_timeout)

    assert received_event is not None


def test_api_failure(scoped_provider):
    provider = scoped_provider
    # assert that the cloud
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    def side_effect(*a, **k):
        raise CloudTemporaryError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        with patch.object(provider, "api_retry", False):
            with pytest.raises(CloudTemporaryError):
                provider.exists_path("/notexists")


def test_file_not_found(provider):
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    def new_fake_oid(oid=None):
        retval = oid if oid else os.urandom(16).hex()
        if provider.name == "dropbox":
            retval = 'id:' + retval
        return retval

    test_file_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_file_deleted_info = provider.create(test_file_deleted_path, data(), None)
    test_file_deleted_oid = test_file_deleted_info.oid
    provider.delete(test_file_deleted_oid)

    test_folder_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_folder_deleted_oid = provider.mkdir(test_folder_deleted_path)
    provider.delete(test_folder_deleted_oid)

    test_path_made_up = provider.temp_name("dest2")  # Never created
    test_oid_made_up = new_fake_oid(oid="nevercreated")

    test_existent_file_path = provider.temp_name("dest3")
    test_existent_file_info = provider.create(test_existent_file_path, data(), None)
    test_existent_file_oid = test_existent_file_info.oid

    test_existent_folder_path = provider.temp_name("dest4")
    test_existent_folder_oid = provider.mkdir(test_existent_folder_path)

    # TODO: consider mocking info_path to always return None, and then call all the provider methods
    #  to see if they are handling the None, and not raising exceptions other than FNF

    # Tests:
    #   exists_path
    #       deleted file, returns false, does not raise
    #       deleted folder, returns false, does not raise
    #       never existed fsobj, returns false, does not raise
    assert provider.exists_path(test_file_deleted_path) is False
    assert provider.exists_path(test_folder_deleted_path) is False
    assert provider.exists_path(test_path_made_up) is False

    #   exists_oid
    #       deleted file, returns false, does not raise
    #       deleted folder, returns false, does not raise
    #       never existed fsobj, returns false, does not raise
    assert provider.exists_oid(test_file_deleted_oid) is False
    assert provider.exists_oid(test_folder_deleted_oid) is False
    assert provider.exists_oid(test_oid_made_up) is False

    #   info_path
    #       deleted file returns None
    #       deleted folder returns None
    #       never existed fsobj returns None
    assert provider.info_path(test_file_deleted_path) is None
    assert provider.info_path(test_folder_deleted_path) is None
    assert provider.info_path(test_path_made_up) is None

    #   info_oid
    #       deleted file returns None
    #       deleted folder returns None
    #       never existed fsobj returns None
    assert provider.info_oid(test_file_deleted_oid) is None
    assert provider.info_oid(test_folder_deleted_oid) is None
    assert provider.info_oid(test_oid_made_up) is None

    #   hash_oid
    #       deleted file returns None
    #       never existed file returns None
    # if getattr(provider, "hash_oid", False): # TODO implement hash_oid in gdrive, then don't have this be conditional
    #     assert provider.hash_oid(test_file_deleted_oid) is None
    #     assert provider.hash_oid(test_oid_made_up) is None

    #   upload
    #       to a deleted file raises FNF, or untrashes the file, either is OK
    #       to a made up oid raises FNF
    # TODO: uploading to a deleted file might not raise an FNF, it might just untrash the file
    assert provider.exists_oid(test_file_deleted_oid) is False
    assert provider.exists_path(test_file_deleted_path) is False
    try:
        info = provider.upload(test_file_deleted_oid, data(), None)
        # This succeeded so the file must exist now, at the same oid as before
        assert info.oid == test_file_deleted_oid
        assert provider.exists_path(test_file_deleted_path) is True
        assert provider.exists_oid(test_file_deleted_oid) is True
        re_delete = True
    except CloudFileNotFoundError:
        re_delete = False
        pass
    if re_delete:
        provider.delete(test_file_deleted_oid)

    with pytest.raises(CloudFileNotFoundError):
        provider.upload(test_oid_made_up, data(), None)

    #   create
    #       to a non-existent folder, raises FNF
    #       to a previously deleted folder, raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.create(test_path_made_up + "/junk", data(), None)
    with pytest.raises(CloudFileNotFoundError):
        provider.create(test_folder_deleted_path + "/junk", data(), None)

    #   upload: to the OID of a deleted folder, raises FNFE
    with pytest.raises(CloudFileNotFoundError):
        provider.upload(test_folder_deleted_oid, data(), None)

    #   download
    #       on a deleted oid raises FNF
    #       on a made up oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_file_deleted_oid, data())
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_oid_made_up, data())

    #   rename

    #       from a deleted oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_file_deleted_oid, test_file_deleted_path)
    #       from a deleted oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_folder_deleted_oid, test_folder_deleted_path)
    #       from a made up oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_oid_made_up, test_path_made_up)
    #       rename /a to /b/c where b does not exist, raises file not found
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_existent_file_oid, test_path_made_up + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_existent_folder_oid, test_path_made_up + "/junk")
    #       rename /a to /b/c where b was previously deleted, raises file not found
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_existent_file_oid, test_file_deleted_path + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_existent_folder_oid, test_folder_deleted_path + "/junk")
    #       TODO: check the rename source to see if there are others
    #       TODO: rename /a to /a/b raises [something]
    #       TODO: rename /a to /a/b/c where b exists, raises [the same something]
    #       rename /a to /a/b/c where b does not exist, raises file not found
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_existent_file_oid, test_existent_folder_path + "/junk/junkier")
        provider.rename(test_existent_folder_oid, test_existent_folder_path + "/junk/junkier")

    #   mkdir
    #       to a non-existent folder raises FNF
    #       to a previously deleted folder as parent folder raises FNF
    #       to a previously deleted file as parent folder raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_path_made_up + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_folder_deleted_path + "/junk")
    with pytest.raises(CloudFileNotFoundError):
        provider.mkdir(test_file_deleted_path + "/junk")

    #   delete
    #       on a deleted file oid does not raise
    #       on a deleted folder oid does not raise
    #       on a made up oid does not raise
    provider.delete(test_file_deleted_oid)
    provider.delete(test_folder_deleted_oid)
    provider.delete(test_oid_made_up)

    # delete: create a file, delete it, then create a new file at that path, then re-delete the deleted oid, raises FNFE
    temp_path = provider.temp_name()
    info1 = provider.create(temp_path, BytesIO(b"Hello"))
    provider.delete(info1.oid)
    info2 = provider.create(temp_path, BytesIO(b"world"))
    if provider.oid_is_path:
        assert provider.exists_oid(info1.oid)
        assert provider.exists_path(temp_path)
        assert provider.exists_oid(info2.oid)
    else:
        assert not provider.exists_oid(info1.oid)
        assert provider.exists_oid(info2.oid)
        provider.delete(info1.oid)
        assert provider.exists_path(temp_path)
        assert provider.exists_oid(info2.oid)

    #   listdir
    #       on a deleted file raises FNF
    #       on a deleted folder raises FNF
    #       on a made up path raises FNF
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_file_deleted_oid))
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_folder_deleted_oid))
    with pytest.raises(CloudFileNotFoundError):
        list(provider.listdir(test_oid_made_up))

    # TODO: Google drive raises FNF when it can't find the root... can we test for that here?


def test_file_exists(provider):
    dat = os.urandom(32)

    def data(da=dat):
        return BytesIO(da)

    def create_and_delete_file():
        create_and_delete_file_name = provider.temp_name()
        file_info = provider.create(create_and_delete_file_name, data(), None)
        provider.delete(file_info.oid)
        return create_and_delete_file_name, file_info.oid

    def create_and_delete_folder():
        create_and_delete_folder_name = provider.temp_name()
        create_and_delete_folder_oid = provider.mkdir(create_and_delete_folder_name)
        provider.delete(create_and_delete_folder_oid)
        return create_and_delete_folder_name, create_and_delete_folder_oid

    def create_and_rename_file():
        file_name1 = provider.temp_name()
        file_name2 = provider.temp_name()
        assert file_name1 != file_name2
        file_info1 = provider.create(file_name1, data(), None)
        provider.rename(file_info1.oid, file_name2)
        return file_name1, file_info1.oid

    def create_and_rename_folder():
        folder_name1 = provider.temp_name()
        folder_name2 = provider.temp_name()
        assert folder_name1 != folder_name2
        folder_oid1 = provider.mkdir(folder_name1)
        provider.rename(folder_oid1, folder_name2)
        return folder_name1, folder_oid1

    def create_file(create_file_name=None):
        if create_file_name is None:
            create_file_name = provider.temp_name()
        file_info = provider.create(create_file_name, data(), None)
        return create_file_name, file_info.oid

    def create_folder(create_folder_name=None):
        if create_folder_name is None:
            create_folder_name = provider.temp_name()
        create_folder_oid = provider.mkdir(create_folder_name)
        return create_folder_name, create_folder_oid

    # Test that operations on existent file system objects raise CloudExistsError
    # when appropriate, and don't when inappropriate
    # api methods to check for FileExists:
    #   vulnerable to existing paths:
    #       mkdir, create, rename
    #   Possible issues to potentially check each of the vulnerable api methods:
    #       target path has a component in the parent folder that already exists as a file
    #       target path exists
    #       target path exists, but the type of the existing object at that location is different from expected
    #       target path exists, but the type of the existing object at that location is what was expected
    #       target path existed, but was deleted, different type as source
    #       target path existed, but was deleted, same type as source
    #       target path existed, but was renamed, different type as source
    #       target path existed, but was renamed, same type as source
    #
    #   vulnerable to existing OIDs:
    #       upload, delete
    #   Possible issues to potentially check each of the vulnerable api methods:
    #       target OID exists, but the type of the existing object at that location is different from expected
    #       target OID existed, but was trashed, should un-trash the object
    #       target OID is a non-empty folder, delete should raise FEx
    #

    # The enumerated tests:
    #   mkdir: where target path has a parent folder that already exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.mkdir(name + "/junk")

    #   mkdir: where target path exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.mkdir(name)

    #   mkdir: where target path exists as a folder, does not raise
    name1, oid1 = create_folder()
    oid2 = provider.mkdir(name1)
    assert oid1 == oid2

    #   mkdir: creating a file, deleting it, then creating a folder at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_file()
    oid2 = provider.mkdir(name1)
    assert oid1 != oid2 or provider.oid_is_path

    #   mkdir: creating a folder, deleting it, then creating a folder at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_folder()
    oid2 = provider.mkdir(name1)
    assert oid1 != oid2 or provider.oid_is_path

    #   mkdir: target path existed as file, but was renamed
    name1, oid1 = create_and_rename_file()
    _, oid2 = create_folder(name1)
    assert oid1 != oid2 or provider.oid_is_path

    #   mkdir: target path existed as folder, but was renamed
    name1, oid1 = create_and_rename_folder()
    _, oid2 = create_folder(name1)
    assert oid1 != oid2 or provider.oid_is_path

    #   upload: where target OID is a folder, raises FEx
    _, oid1 = create_folder()
    with pytest.raises(CloudFileExistsError):
        provider.upload(oid1, data(), None)

    #   delete: a non-empty folder, raises FEx
    name1, oid1 = create_folder()
    create_file(name1 + "/junk")
    with pytest.raises(CloudFileExistsError):
        provider.delete(oid1)

    #   create: where target path exists, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        create_file(name)

    def get_contents(oid):
        temp_contents = BytesIO()
        provider.download(oid, temp_contents)
        temp_contents.seek(0)
        return temp_contents.getvalue()

    #   create: creating a file, deleting it, then creating a file at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_file()
    _, oid2 = create_file(name1)
    assert oid1 != oid2 or provider.oid_is_path
    if provider.oid_is_path:
        assert provider.exists_oid(oid1)
    else:
        assert not provider.exists_oid(oid1)

    assert provider.exists_oid(oid2)
    # piggyback test -- uploading to the deleted oid should not step on the file that replaced it at that path
    if not provider.oid_is_path:
        try:
            new_contents = b"yo"  # bytes(os.urandom(16).hex(), 'utf-8')
            new_info = provider.upload(oid1, BytesIO(new_contents))
            assert new_info.oid != oid1
            assert new_info.oid != oid2
            assert not provider.exists_oid(oid1)
            contents2 = get_contents(oid2)
            assert contents2 == new_contents
            contents1 = get_contents(oid1)
            assert contents1 == new_contents
        except CloudFileNotFoundError:
            pass

    #   create: creating a folder, deleting it, then creating a file at the same path, should not raise an FEx
    name1, oid1 = create_and_delete_folder()
    _, oid2 = create_file(name1)
    assert oid1 != oid2 or provider.oid_is_path

    #   create: where target path has a parent folder that already exists as a file, raises FEx
    name, _ = create_file()
    with pytest.raises(CloudFileExistsError):
        create_file(name + "/junk")

    #   create: target path existed as folder, but was renamed
    name, _ = create_and_rename_folder()
    create_file(name)

    #   create: target path existed as file, but was renamed
    name, _ = create_and_rename_file()
    create_file(name)

    #   rename: rename folder over empty folder succeeds
    name1, oid1 = create_folder()
    create_file(name1 + "/junk")
    name2, oid2 = create_folder()
    assert oid1 != oid2
    contents1 = [x.name for x in provider.listdir(oid1)]
    provider.rename(oid1, name2)
    if provider.oid_is_path:
        log.debug("oid1 %s, oid2 %s", oid1, oid2)
        assert not provider.exists_oid(oid1)
        assert provider.exists_oid(oid2)
        contents2 = [x.name for x in provider.listdir(oid2)]
    else:
        assert provider.exists_oid(oid1)
        assert not provider.exists_oid(oid2)
        contents2 = [x.name for x in provider.listdir(oid1)]
    assert contents1 == contents2

    #   rename: rename folder over non-empty folder raises FEx
    _, oid1 = create_folder()
    name2, oid2 = create_folder()
    assert oid1 != oid2
    create_file(name2 + "/junk")
    with pytest.raises(CloudFileExistsError):
        provider.rename(oid1, name2)

    #   rename: target has a parent folder that already exists as a file, raises FEx
    folder_name, _ = create_file()  # notice that I am creating a file, and calling it a folder
    with pytest.raises(CloudFileExistsError):
        create_file(folder_name + "/junk")

    #   rename: renaming file over empty folder, raises FEx
    folder_name, folder_oid = create_folder()
    file_name, file_oid = create_file()
    other_file_name, other_file_oid = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.rename(file_oid, folder_name)

    #   rename: renaming file over non-empty folder, raises FEx
    create_file(folder_name + "/test")
    with pytest.raises(CloudFileExistsError):
        provider.rename(file_oid, folder_name)  # reuse the same file and folder from the last test

    #   rename: renaming a folder over a file, raises FEx
    with pytest.raises(CloudFileExistsError):
        provider.rename(folder_oid, file_name)  # reuse the same file and folder from the last test

    #   rename: renaming a file over a file, raises FEx
    with pytest.raises(CloudFileExistsError):
        provider.rename(file_oid, other_file_name)  # reuse the same file and folder from the last test

    #   rename: create a file, delete it, then rename a file to the same path as the deleted, does not raise
    deleted_file_name, deleted_file_oid = create_and_delete_file()
    name2, oid2 = create_file()
    provider.rename(oid2, deleted_file_name)

    #   rename: create a folder, delete it, then rename file to the same path as the deleted, does not raise
    deleted_folder_name, deleted_folder_oid1 = create_and_delete_folder()
    name2, oid2 = create_file()
    provider.rename(oid2, deleted_folder_name)

    #   rename: create a file, delete it, then rename a folder to the same path as the deleted, does not raise
    deleted_file_name, deleted_file_oid = create_and_delete_file()
    name2, oid2 = create_folder()
    provider.rename(oid2, deleted_file_name)

    #   rename: create a folder, delete it, then rename folder to the same path as the deleted, does not raise
    deleted_folder_name, deleted_folder_oid1 = create_and_delete_folder()
    name2, oid2 = create_folder()
    provider.rename(oid2, deleted_folder_name)

    #   rename: target folder path existed, but was renamed away, folder type as source
    name1, oid1 = create_and_rename_folder()
    name2, oid2 = create_folder()
    provider.rename(oid2, name1)

    #   rename: target folder path existed, but was renamed away, file type as source
    name1, oid1 = create_folder()
    name2, oid2 = create_file()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)

    #   rename: target file path existed, but was renamed away, folder type as source
    name1, oid1 = create_file()
    name2, oid2 = create_folder()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)

    #   rename: target file path existed, but was renamed away, file type as source
    name1, oid1 = create_file()
    name2, oid2 = create_file()
    temp = provider.temp_name()
    provider.rename(oid1, temp)
    provider.rename(oid2, name1)


def test_file_exists_error_file_in_path(provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    def create_file(create_file_name=None):
        if create_file_name is None:
            create_file_name = provider.temp_name()
        file_info = provider.create(create_file_name, data(), None)
        return create_file_name, file_info.oid

    def create_folder(create_folder_name=None):
        if create_folder_name is None:
            create_folder_name = provider.temp_name()
        create_folder_oid = provider.mkdir(create_folder_name)
        return create_folder_name, create_folder_oid

    #   rename: target file path contains a file, raises FEx
    name1, oid1 = create_file()
    name2, oid2 = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.rename(oid1, name2 + provider.temp_name())

    #   rename target folder path contains a file raises FEx
    name1, oid1 = create_folder()
    name2, oid2 = create_file()
    with pytest.raises(CloudFileExistsError):
        provider.rename(oid1, name2 + provider.temp_name())


def test_cursor(provider):
    if provider.prov.name == 'gdrive':
        # TODO: fix this, why is gdrive unreliable at event delivery?
        pytest.xfail("gdrive is flaky")
    # get the ball rolling
    provider.create("/file1", BytesIO(b"hello"))
    for i in provider.events():
        log.debug("event = %s", i)
    current_csr1 = provider.current_cursor
    log.debug(f"type of cursor is {type(current_csr1)}")
    provider.current_cursor = current_csr1  # test the setter

    # do something to create an event
    log.debug(f"csr1={current_csr1} current={provider.current_cursor} latest={provider.latest_cursor}")
    info = provider.create("/file2", BytesIO(b"there"))
    log.debug(f"current={provider.current_cursor} latest={provider.latest_cursor} oid={info.oid}")
    found = False
    # NOTE: will hang for 10 min if event does not come through
    for e in provider.events_poll(timeout=600, until=lambda: found):
        log.debug("event = %s", e)
        if e.oid == info.oid:
            found = True
    assert found

    current_csr2 = provider.current_cursor
    log.debug(f"current={provider.current_cursor} latest={provider.latest_cursor} oid={info.oid}")

    if (current_csr1 is None and current_csr2 is None):
        # some providers don't support cursors... they will walk on start, always
        return

    assert current_csr1 != current_csr2

    # check that we can go backwards
    provider.prov._clear_cache()
    provider.current_cursor = current_csr1
    log.debug(f"current={provider.current_cursor} latest={provider.latest_cursor} oid={info.oid}")
    found = False
    for i in provider.events_poll(timeout=10, until=lambda: found):
        log.debug("event = %s", i)
        if i.oid == info.oid:
            found = True
    assert found

# TODO: test that renaming A over B replaces B's OID with A's OID, and B's OID is trashed


def test_listdir(provider):
    outer = provider.temp_name()
    root = provider.dirname(outer)
    temp_name = provider.is_subpath(root, outer)

    try:
        list(provider.listdir_path(outer))
        assert False
    except CloudFileNotFoundError:
        pass

    outer_oid_rm = provider.mkdir(outer)
    assert [] == list(provider.listdir(outer_oid_rm))
    provider.delete(outer_oid_rm)

    outer_oid = provider.mkdir(outer)

    assert provider.exists_path(outer)
    assert provider.exists_oid(outer_oid)
    old_list = provider.listdir(outer_oid)
    inner = outer + temp_name
    inner_oid = provider.mkdir(inner)
    assert provider.exists_oid(inner_oid)
    new_list = provider.listdir(outer_oid)
    assert old_list != new_list  # confirm that the folder contents are not cached
    provider.create(outer + "/file1", BytesIO(b"hello"))
    provider.create(outer + "/file2", BytesIO(b"there"))
    provider.create(inner + "/file3", BytesIO(b"world"))
    contents = list(provider.listdir(outer_oid))
    assert all([x.oid for x in contents])
    assert all([x.otype for x in contents])
    names = [x.name for x in contents]
    assert len(names) == 3
    expected = ["file1", "file2", temp_name[1:]]
    log.info("names %s", names)
    assert sorted(names) == sorted(expected)

    paths1 = [x.path for x in contents]
    contents2 = list(provider.listdir_oid(outer_oid, path=outer))
    paths2 = [x.path for x in contents2]
    assert all(paths2)
    if any(paths1):
        assert sorted(paths1) == sorted(paths2)


def test_listdir_paginates(provider):
    root = '/' + os.urandom(16).hex()
    root_oid = provider.mkdir(root)
    if not provider._listdir_page_size:
        pytest.skip("provider doesn't support listdir pagination")

    provider._listdir_page_size = 5
    for _ in range(provider._listdir_page_size):
        provider.mkdir(root + "/" + os.urandom(16).hex())
    assert len(list(provider.listdir(root_oid))) == provider._listdir_page_size

    provider.mkdir(root + "/" + os.urandom(16).hex())
    assert len(list(provider.listdir(root_oid))) == provider._listdir_page_size + 1


def test_upload_to_a_path(provider):
    temp_name = provider.temp_name()
    info = provider.create(temp_name, BytesIO(b"test"))
    assert info.hash
    # test uploading to a path instead of an OID. should raise something
    # This test will need to flag off whether the provider uses paths as OIDs or not
    with pytest.raises(Exception):
        info = provider.upload(temp_name, BytesIO(b"test2"))


def test_upload(provider):
    temp_name = provider.temp_name()
    info = provider.create(temp_name, BytesIO(b"test"))
    assert info.hash
    provider.upload(info.oid, BytesIO(b"test2"))


def test_upload_zero_bytes(provider):
    temp_name = provider.temp_name()
    info = provider.create(temp_name, BytesIO(b""))
    info2 = provider.upload(info.oid, BytesIO(b""))
    dest = BytesIO()
    provider.download(info.oid, dest)
    assert info
    assert info2
    assert info.hash == info2.hash


def test_delete_doesnt_cross_oids(provider):
    temp_name = provider.temp_name()
    info1 = provider.create(temp_name, BytesIO(b"test1"))
    provider.delete(info1.oid)
    info2 = provider.create(temp_name, BytesIO(b"test2"))
    if not provider.oid_is_path:
        assert info1.oid != info2.oid
        assert not provider.exists_oid(info1.oid)
    assert provider.exists_oid(info2.oid)

    if not provider.oid_is_path:
        provider.delete(info1.oid)
        assert not provider.exists_oid(info1.oid)
        assert provider.exists_oid(info2.oid)

    # test uploading to a path instead of an OID. should raise something
    # This test will need to flag off whether the provider uses paths as OIDs or not
    with pytest.raises(Exception):
        provider.upload(temp_name, BytesIO(b"test2"))


def test_exists_oid(provider):
    file_name = provider.temp_name()
    file_info = provider.create(file_name, BytesIO(os.urandom(32)))
    provider._clear_cache()
    assert(provider.exists_oid(file_info.oid))

    provider.delete(file_info.oid)
    assert(not provider.exists_oid(file_info.oid))


@pytest.mark.parametrize("otype", ["file", "folder"])
def test_rename_case_change(provider, otype):
    temp_namel = provider.temp_name().lower()
    temp_nameu = temp_namel.upper()
    if otype == "file":
        infol = provider.create(temp_namel, BytesIO(b"test"))
    else:
        l_oid = provider.mkdir(temp_namel)
        infol = provider.info_oid(l_oid)
    assert infol.path == temp_namel
    new_oid = provider.rename(infol.oid, temp_nameu)
    assert new_oid
    infou = provider.info_oid(new_oid)
    assert infou.path == temp_nameu
    infopu = provider.info_path(temp_nameu)
    infopl = provider.info_path(temp_namel)

    assert infopu
    assert infopu.path == temp_nameu

    if provider.case_sensitive:
        assert not infopl
    else:
        assert infopl
        assert infopl.path == temp_nameu


def test_report_info(provider):
    assert provider.name
    temp_name = provider.temp_name()

    u1 = provider.get_quota()["used"]
    log.info("used %s", u1)

    provider.create(temp_name, BytesIO(b"test" * 100000))

    time.sleep(1)

    pinfo2 = provider.get_quota()

    # note this may be memoized (gdrive does this internally)
    # so there is no guarantee that the used != 0 afer create
    # or that creating a file increases used
    # so providers need to implement this *at least* for create
    # otherwise this info is not helpful for uploads
    # todo: more extensive provider requirements on cached quotas

    log.info("info %s", pinfo2)

    assert pinfo2['used'] > 0
    assert pinfo2['limit'] > 0
    if provider.name not in ("box", "filesystem"):
        # box cache defeats this
        # fs providers have too many temp files blinking in and out
        assert pinfo2['used'] > u1


def test_quota_limit(mock_provider):
    mock_provider._set_quota(1024)
    mock_provider.create("/foo", BytesIO(b'0' * 1024))
    with pytest.raises(CloudOutOfSpaceError):
        mock_provider.create("/bar", BytesIO(b'0' * 2))
    assert not mock_provider.info_path("/bar")


class FakeFile:
    def __init__(self, size, repeat=b'0'):
        self.loc = 0
        self.size = size
        self.repeat = repeat
        self.closed = False

    def fileno(self):
        raise io.UnsupportedOperation()

    def write(self, data):
        raise io.UnsupportedOperation()

    def read(self, size=None):
        if size is None:
            size = self.size
        end = min(self.loc + size, self.size)
        size = end - self.loc
        if size <= 0:
            return b''
        self.loc += size
        return self.repeat * size

    def seek(self, offset, whence=SEEK_SET):
        if whence == SEEK_SET:
            self.loc = offset
        elif whence == SEEK_END:
            self.loc = self.size - offset
        elif whence == SEEK_CUR:
            self.loc += offset
        return

    def seekable(self):
        return True

    def close(self):
        self.closed = True

    def tell(self):
        return self.loc


def test_large_file_support(provider):
    # fix multipart upload size to something small
    if not provider.large_file_size:
        pytest.skip("provider doesn't need multipart tests")

    provider.large_file_size = 4 * 1024 * 1024
    provider.upload_block_size = 1 * 1024 * 1024
    target_size = 6 * 1024 * 1024
    fh = FakeFile(target_size, repeat=b'0')
    provider.create("/foo", fh)
    info = provider.info_path("/foo")
    assert info
    fh = FakeFile(target_size, repeat=b'1')
    provider.upload(info.oid, fh)
    log.debug("info=%s", info)
    root_info = provider.info_path("/")
    assert root_info
    dir_list = list(provider.listdir(root_info.oid))
    log.debug("dir_list=%s", dir_list)
    new_fh = BytesIO()
    provider.download_path("/foo", new_fh)
    new_fh.seek(0)
    assert new_fh.read(10) == b'1111111111'
    new_fh.seek(0, SEEK_END)
    new_len = new_fh.tell()
    assert new_len == target_size


def test_special_characters(provider):
    log.debug("start")
    fname = ""
    additional_invalid_characters = getattr(provider, "_additional_invalid_characters", "")
    for i in range(32, 127):
        char = str(chr(i))
        if char in (provider.sep, provider.alt_sep):
            continue
        if char in """<>:"/\\|?*""":
            continue
        if char in additional_invalid_characters:
            continue
        fname = fname + str(chr(i))
    fname = "/fn-" + fname
    log.debug("fname = %s", fname)
    contents = b"hello world"
    info = provider.create(fname, BytesIO(contents))
    log.debug("info = %s", info)
    info2 = provider.info_path(fname)
    assert info2.oid == info.oid
    catch = BytesIO()
    provider.download(info.oid, catch)
    assert catch.getvalue() == contents
    # also test rename, mkdir, info_path, exists_path
    fname2 = fname + ".2"
    log.debug("fname2 = %s", fname2)
    new_oid = provider.rename(info.oid, fname2)
    info3 = provider.info_oid(new_oid)
    assert provider.exists_path(fname2)
    assert provider.info_path(fname2).oid == new_oid
    dirname = fname + ".dir"
    diroid = provider.mkdir(dirname)
    dirinfo = provider.info_path(dirname)
    assert dirinfo.otype == cloudsync.DIRECTORY
    assert dirinfo.oid == diroid
    newfname2 = provider.join(dirname, fname2)
    new_oid2 = provider.rename(new_oid, newfname2)
    test_newfname2 = provider.info_oid(new_oid2)
    newfname2info = provider.info_path(newfname2)
    assert newfname2info
    assert newfname2info.oid == new_oid2
    log.debug("done")


def test_cursor_error_during_listdir(provider):
    if provider.name != "dropbox":
        pytest.skip("dropbox specific test")

    provider.current_cursor = provider.latest_cursor

    dir_name = provider.temp_name()
    dir_oid = provider.mkdir(dir_name)
    provider.create(dir_name + "/file1", BytesIO(b"hello"))
    provider.create(dir_name + "/file2", BytesIO(b"there"))

    # listdir should not accidentally raise a cursor error (dropbox uses cursors for listing folders)
    def new_api(*a, **k):
        raise CloudCursorError("cursor error")
    orig_api = provider._api
    provider._api = new_api
    with pytest.raises(CloudTemporaryError):
        list(provider.listdir(dir_oid))
    provider._api = orig_api


def test_set_creds(config_provider):
    provider = ProviderTestMixin(config_provider, connect=False)      # type: ignore
    if not provider._test_creds:
        pytest.skip("provider doesn't support testing creds")
    provider.set_creds(provider._test_creds)
    provider.reconnect()
    assert provider.connected


def test_set_ns_offline(unwrapped_provider):
    provider = ProviderTestMixin(unwrapped_provider, connect=False)      # type: ignore
    try:
        provider.list_ns()
        pytest.skip("provider doesn't use online namespace listings")
    except CloudDisconnectedError:
        pass

    provider.namespace_id = 'bad-namespace-is-ok-at-least-when-offline'
    log.info("ns id %s", provider.namespace_id)
    with pytest.raises(CloudNamespaceError):
        provider.connect(provider._test_creds)
    assert provider.namespace is None  # setting a bad ns id makes this None
    with pytest.raises(CloudNamespaceError):
        provider.namespace_id = 'bad-namespace-is-not-ok-when-online'


@pytest.mark.manual
def test_authenticate(unwrapped_provider):
    provider = ProviderTestMixin(unwrapped_provider, connect=False)      # type: ignore
    if not provider._test_creds:
        pytest.skip("provider doesn't support testing auth")

    creds = provider.authenticate()
    log.info(creds)
    provider.connect(creds)
    provider.disconnect()
    provider.connect(creds)

    modded = False
    for k, v in creds.items():
        if type(v) is str:
            creds[k] = cast(str, v) + "junk"
            modded = True

    if modded:
        provider.disconnect()
        with pytest.raises(CloudTokenError):
            provider.connect(creds)
        assert not provider.connected


@pytest.mark.manual
def test_interrupt_auth(unwrapped_provider):
    provider = ProviderTestMixin(unwrapped_provider, connect=False)      # type: ignore
    if not provider._test_creds:
        pytest.skip("provider doesn't support testing auth")

    import time
    import threading
    threading.Thread(target=lambda: (time.sleep(0.5), provider.interrupt_auth()), daemon=True).start()  # type: ignore
    with pytest.raises(CloudTokenError):
        provider.authenticate()
    assert not provider.connected


def test_exists_immediately(provider):
    if not provider.prov._clear_cache():
        raise pytest.skip("test only runs if provider implements _clear_cache method")
    root_oid = provider.info_path('/').oid
    dir_name = "/testdir"  # provider.temp_name()
    file_name1 = dir_name + "/file1"
    file_name2 = dir_name + "/file2"

    dir_oid = provider.mkdir(dir_name)
    assert dir_oid
    provider.prov._clear_cache()
    contents = list(provider.listdir(root_oid))
    log.debug("contents=%s", contents)
    oids = [i.oid for i in contents]
    assert dir_oid in oids
    provider.prov._clear_cache()
    oinfo = provider.info_path(dir_name)
    assert oinfo

    file_info1 = provider.create(file_name1, BytesIO(b"hello"))
    file_info2 = provider.create(file_name2, BytesIO(b"hello"))
    provider.prov._clear_cache()
    contents = list(provider.listdir(dir_oid))
    log.debug("contents=%s", contents)
    oids = [i.oid for i in contents]
    assert file_info1.oid in oids
    assert file_info2.oid in oids
    provider.prov._clear_cache()
    oinfo1 = provider.info_path(file_name1)
    oinfo2 = provider.info_path(file_name2)
    assert oinfo1
    assert oinfo2

    provider.delete(file_info1.oid)
    provider.prov._clear_cache()
    contents = list(provider.listdir(dir_oid))
    log.debug("contents=%s", contents)
    oids = [i.oid for i in contents]
    assert file_info1.oid not in oids
    assert file_info2.oid in oids
    provider.prov._clear_cache()
    oinfo1 = provider.info_path(file_name1)
    oinfo2 = provider.info_path(file_name2)
    assert not oinfo1
    assert oinfo2


@pytest.fixture
def suspend_capture(pytestconfig):
    class suspend_guard:
        def __init__(self):
            self.capmanager = pytestconfig.pluginmanager.getplugin('capturemanager')
        def __enter__(self):
            self.capmanager.suspend_global_capture(in_=True)
        def __exit__(self, _1, _2, _3):
            self.capmanager.resume_global_capture()

    yield suspend_guard()


# noinspection PyUnreachableCode
@pytest.mark.manual
def test_revoke_auth(unwrapped_provider, suspend_capture):
    provider = ProviderTestMixin(unwrapped_provider, connect=False)      # type: ignore
    if not provider._test_creds:
        pytest.skip("provider doesn't support testing auth")
    creds = provider.authenticate()
    provider.connect(creds)

    with suspend_capture:
        input("PLEASE GO TO THE PROVIDER AND REVOKE ACCESS NOW")

    with pytest.raises(CloudTokenError):
        # some providers cache connections, so this test may not work for everyone
        while True:
            log.error("sleep 5")
            time.sleep(5)
            log.error("still connected %s, %s", provider.prov.info_path("/"), provider.prov.get_quota())
    assert not provider.connected


# testing the test framework
def test_specific_test_root():
    """
    assure that the provider helper uses the requested test root
    assure it never deletes it
    cryptvfs relies on this
    """

    class MockProvRooted(MockProvider):
        test_root = "/banana"
    base = MockProvRooted(False, False)
    base.connect("whatever")
    base.mkdir("/banana")

    provider = ProviderTestMixin(base)                             # type: ignore
    # i use whatever root the test instance specified
    assert provider.test_root.startswith("/banana/")
    # i but i put my tests in their own folder
    assert provider.test_root != "/banana/"

    # and i created it
    assert base.info_path(provider.test_root).otype == cloudsync.DIRECTORY 

    provider.test_cleanup(connected=True)

    # and i dont delete the test root
    assert list(base.listdir_path("/banana")) == []


def test_provider_interface(unconnected_provider):
    provider = unconnected_provider
    base_dir = set([x for x in dir(Provider) if not x.startswith('_')])
    base_dir = set(dir(Provider))
    log.debug("basedir = %s", base_dir)
    prov_dir = set([x for x in dir(provider.prov) if not x.startswith('_')])
    log.debug("provdir = %s", prov_dir)
    for x in base_dir:
        if x in prov_dir:
            prov_dir.remove(x)
    if len(prov_dir) > 0:
        msg = "provider %s exposes public interfaces not exposed by the base class:" % provider.prov.name
        for x in prov_dir:
            msg += "\n     %s" % x
        log.error(msg)
    assert prov_dir == set()

def test_multi_provider_shutdown(two_scoped_providers):
    # Kind of hacky, could use a timeout wrapper on tests
    MAX_TIME = 10
    start_time = time.monotonic()

    (prov1, prov2) = two_scoped_providers
    
    # Start fresh
    prov1.disconnect()
    prov2.disconnect()

    if hasattr(prov1, "_test_creds"):
        prov1.connect(prov1._test_creds)
    if hasattr(prov2, "_test_creds"):
        prov2.connect(prov2._test_creds)

    prov2.disconnect()
    prov1.disconnect()
    assert not prov1.connected
    assert not prov2.connected

    if hasattr(prov1, "_test_creds"):
        prov1.connect(prov1._test_creds)
    if hasattr(prov2, "_test_creds"):
        prov2.connect(prov2._test_creds)

    prov1.disconnect()
    prov2.disconnect()
    assert not prov1.connected
    assert not prov2.connected

    end_time = time.monotonic()
    if (end_time - start_time > MAX_TIME):
        raise TimeoutError("Connect/Disconnect taking too long")

def test_cache(two_scoped_providers):
    (prov1, prov2) = two_scoped_providers
    assert prov1 is not prov2
    assert prov1.prov is not prov2.prov

    # First, determine if the provider uses caching
    #   - create a file using prov1
    #   - check existence using prov2 to cache it
    #   - delete the file using prov1
    #   - check existence using prov2. If it exists, it's cached. If not, then the provider class isn't caching
    cache_test_info = prov1.create("/cachetest", BytesIO(b"cachetests"))
    if not prov2.exists_path("/cachetest"):
        pytest.skip("can't test caching if provider does not implement shared storage mechanism")
    prov1.delete(cache_test_info.oid)
    if not prov2.exists_path("/cachetest"):
        pytest.skip("provider apparently doesn't use caching")

    # apparently, the provider does use caching, so now proceed to ensure it is used correctly

    # test to make sure the provider implements _clear_cache. all caching providers must do this.
    assert prov1.prov._clear_cache()

    # test to make sure that deleting a folder causes the folder's kids to be uncached
    folder_name = "/folder"
    file_name = folder_name + "/file1"
    folder_oid = prov1.mkdir(folder_name)
    file1_info = prov1.create(file_name, BytesIO(b"hello, world"))
    assert prov1.exists_path(folder_name)
    assert prov1.exists_path(file_name)
    # delete the file using provider2, emptying the folder, so that provider1 can delete the folder while the file
    # still exists in the cache, but not on the shared filesystem
    prov2.delete(file1_info.oid)
    prov1.delete(folder_oid)
    # file should have been removed from the cache on prov1 when the folder was deleted
    assert not prov1.exists_path("/folder/file1")

    # test to make sure that renaming a folder renames the kids
    old_folder_name = "/folder2"
    new_folder_name = "/folder3"
    old_file_name = old_folder_name + "/file2"
    new_file_name = new_folder_name + "/file2"
    folder_oid = prov1.mkdir(old_folder_name)
    prov1.create(old_file_name, BytesIO(b"hello, world"))
    prov1.prov._clear_cache()
    assert prov1.exists_path(old_file_name)
    prov1.rename(folder_oid, new_folder_name)
    assert not prov1.exists_path(old_file_name)
    assert prov1.exists_path(new_file_name)


def test_bug_create(very_scoped_provider):
    provider = very_scoped_provider
    if provider.name == "box":
        # TODO: box needs some mechanism for failing an upload
        # right now, it just creates a zero byte file
        # removing use of the sdk should fix
        raise pytest.skip("box issue, skipping for now")

    def raises_ex(*a, **kw):
        raise OSError("some os problem reading - not a base exception")

    with patch.object(provider, "api_retry", False):
        file_like = BytesIO(b"hello")

        file_like.read = raises_ex          # type: ignore

        with pytest.raises(Exception):
            try:
                provider.create("/bug_create", file_like)
            except Exception as e:
                log.info("Found expected exception: %s", repr(e))
                raise

        assert not provider.exists_path("/bug_create")

    file_like = BytesIO(b"hello")

    def raises_tmp(*a, **kw):
        # if the underlying api calls raise a temp error, then...
        raise CloudTemporaryError("cloud temp error")

    with patch.object(provider, "_api", raises_tmp), patch.object(provider, "_test_event_timeout", .0001):
        with pytest.raises(CloudTemporaryError):
            provider.create("/bug_create", file_like)

    assert not provider.exists_path("/bug_create")


def test_root_rename(unwrapped_provider):
    provider = unwrapped_provider
    if hasattr(provider, "_test_creds"):
        provider.connect(provider._test_creds)
    if hasattr(provider, "_test_namespace"):
        provider.namespace = provider._test_namespace
    tfn1 = provider.join(provider.test_root, os.urandom(24).hex())
    tfn2 = provider.join(provider.test_root, os.urandom(24).hex())
    oinfo = provider.create(tfn1, BytesIO(b'hello'))
    oid = provider.rename(oinfo.oid, tfn2)
    provider.delete(oid)


def test_connect_saves_creds(unwrapped_provider):
    provider = unwrapped_provider
    if not hasattr(provider, "_test_creds") or not provider._test_creds:
        pytest.skip("need creds")
    # a) uses an api function
    # b) does not trap CloudTemporaryError's
    # c) saves the creds even if the api raises

    def side_effect(*a, **k):
        raise CloudDisconnectedError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        assert not provider.connected
        creds = provider._test_creds
        with pytest.raises(CloudDisconnectedError):
            provider.connect(creds)
    provider.reconnect()
    assert provider.connected


small_fsize = 600 * 1024  # 600 KiB
large_fsize = (4 * 1024 * 1024) * 5  # 20 MiB. Note that we upload in chunks of 4 MiB.


@pytest.mark.parametrize("content_len", (small_fsize, large_fsize), ids=("small", "large"))
@pytest.mark.parametrize("operation", ["create", "upload"])
def test_broken_upload(very_scoped_provider, content_len, operation):
    provider = very_scoped_provider
    # Explicitly disable API retries to make logs simpler
    provider.api_retry = False
    assert provider.connected

    contents = b"a" * content_len

    class SleepyIO:
        """Simulate BytesIO, with the addition of an EIO on reads after the
        first half of the file.

        Used to simulate strange, unexpected errors in the uploader.
        """
        def __init__(self, *args, **kwargs):
            self._b = BytesIO(*args, **kwargs)
            self.len = len(self._b.getvalue())

            # Pass these functions through
            self.seek = self._b.seek
            self.tell = self._b.tell

        def read(self, size=-1):
            max_offset = content_len // 2
            req_offset = self._b.tell() + size

            # Check if the requested offset would go too far, or whether a read
            # of the entire file was requested.
            if req_offset > max_offset or (size < 0 or size is None):
                log.info("SleepyIO: Raising EIO")
                raise OSError(errno.EIO, "Fake IOError")

            return self._b.read(size)

    path = f"/truncated_file_{content_len}_{operation}.txt"

    # By default, assume that the full file will be uploaded
    expected_fsize = content_len

    # If we're testing upload, we need to pre-create the file
    if operation == "upload":
        upload_info = provider.create(path, BytesIO())

    # Note: reenable this patch to get extra logging
    try:
        if operation == "create":
            info = provider.create(path, SleepyIO(contents))
        else:
            info = provider.upload(upload_info.oid, SleepyIO(contents))

        log.info("Exception not raised: info is %s", info)

        # If we get an oid, we expect the file to exist now
        expect_path_exists = info is not None
    except (OSError, CloudDisconnectedError, CloudTemporaryError) as e:
        log.info("Got exception in op: %s", repr(e))

        if operation == "create":
            expect_path_exists = False
        else:
            expect_path_exists = True
            expected_fsize = 0

    log.info("Done with upload. File expected to exist: %s", expect_path_exists)

    for _ in range(10):
        if provider.exists_path(path):
            break
        time.sleep(0.1)

    path_exists = provider.exists_path(path)

    if expect_path_exists:
        assert path_exists
    else:
        assert not path_exists

    if path_exists:
        log.info("Downloading file")
        data = BytesIO()
        provider.download_path(path, data)

        data_len = len(data.getvalue())
        assert (
            expected_fsize == data_len
        ), "File existed in the cloud, but had incorrect size"


def test_globalize_root(provider):
    # top path (do the subpath first, in order to test the sharing related code paths for case preservation)
    top_info = provider.info_path("/")
    top_gid = provider.globalize_oid(top_info.oid)
    top_oid = provider.localize_oid(top_gid)
    assert top_info.oid == top_oid


def test_globalize_subfolder(provider):
    # subpath
    sub_oid = provider.mkdir("/Sub")
    sub_gid = provider.globalize_oid(sub_oid)
    sub_info = provider.info_oid(sub_oid)
    assert sub_info.path == "/Sub"  # double check the name and case haven't changed when globalizing

    sub_local_oid = provider.localize_oid(sub_gid)
    assert sub_oid == sub_local_oid



    if sub_gid == sub_local_oid:
        pytest.skip("Provider oid == gid, skipping globalize/localize tests")

    # localize deleted
    provider.delete(sub_oid)
    not_oid = provider.localize_oid(sub_gid)
    assert not_oid is None

    # globalize deleted
    gid = provider.globalize_oid(sub_oid)
    assert gid is None

    # wrong value
    with pytest.raises(ValueError):
        provider.localize_oid(sub_oid)


def test_split(provider):
    assert provider.split("/a/b") == ("/a", "b")
    assert provider.split("\\a\\b") == ("/a", "b")
    assert provider.split("\\") == ("/", "")
    assert provider.split("") == ("", "")
    assert provider.split("a") == ("", "a")


def test_is_subpath(provider):
    assert provider.is_subpath(None, None) == False
    assert provider.is_subpath(None, "") == False
    assert provider.is_subpath(None, "/") == False
    assert provider.is_subpath("/", None) == False
    assert provider.is_subpath("/", "") == False
    assert provider.is_subpath("/", "/a/b") == "/a/b"
    assert provider.is_subpath("\\", "/a\\b\\") == "/a/b"
    assert provider.is_subpath("\\a", "\\a\\b/") == "/b"
    assert provider.is_subpath("\\c", "\\a/b") == False
    assert provider.is_subpath("/c", "\\a/b") == False


def test_replace_path(provider):
    assert provider.replace_path("/a/b", "/a", "/c") == "/c/b"
    assert provider.replace_path("/a/b", "\\a", "\\c") == "/c/b"
    assert provider.replace_path("\\a/b", "\\a", "\\c") == "/c/b"
    assert provider.replace_path("\\a\\b", "\\a", "\\c") == "/c/b"


def test_normalize_path_separators(provider):
    assert provider.normalize_path_separators(None) is None
    assert provider.normalize_path_separators("") == ""
    assert provider.normalize_path_separators("/") == "/"
    assert provider.normalize_path_separators("\\") == "/"
    assert provider.normalize_path_separators("\\a\\b") == "/a/b"
    assert provider.normalize_path_separators("\\\\a\\\\b") == "//a//b"
    assert provider.normalize_path_separators("\\a\\b\\") == "/a/b"
    assert provider.normalize_path_separators("\\a\\b/") == "/a/b"
    assert provider.normalize_path_separators("\\a\\b//") == "/a/b"


@pytest.mark.providers(["mock_path_cs", "mock_oid_ci"])
def test_normalize_path(provider):
    alt_sep = provider.alt_sep or provider.sep

    upper = provider.join(["A", "B", "C", "DEF"])
    lower = provider.join(["a", "b", "c", "def"])
    mixed = provider.join(["A", "b", "C", "dEf"])
    mixed_2 = provider.join(["A", "b", "", "C", "dEf"])
    mixed_alt = alt_sep.join(["A", "b", "C", "dEf"])
    upper_for_display = provider.join(["a", "b", "c", "DEF"])
    mixed_for_display = provider.join(["a", "b", "c", "dEf"])

    if provider.case_sensitive:
        assert provider.normalize_path(upper) == upper
        assert provider.normalize_path(lower) == lower
        assert provider.normalize_path(mixed) == mixed
        assert provider.normalize_path(mixed_alt) == mixed
        assert provider.normalize_path(mixed_2) == mixed
    else:  # case-insensitive
        assert provider.normalize_path(upper) == lower
        assert provider.normalize_path(lower) == lower
        assert provider.normalize_path(mixed) == lower
        assert provider.normalize_path(mixed_alt) == lower
        assert provider.normalize_path(mixed_2) == lower
        # for_display=True must preserve case of leaf path node
        assert provider.normalize_path(upper, for_display=True) == upper_for_display
        assert provider.normalize_path(lower, for_display=True) == lower
        assert provider.normalize_path(mixed, for_display=True) == mixed_for_display
        assert provider.normalize_path(mixed_2, for_display=True) == mixed_for_display


@pytest.mark.providers(["mock_path_cs", "mock_oid_ci"])
def test_paths_match(provider):
    s1 = provider.sep
    s2 = provider.alt_sep or s1

    abcd = ["a", "b", "c", "d"]
    abcd_ = ["a", "b", "c", "d", ""]
    abcD = ["a", "b", "c", "D"]
    abcD_ = ["a", "b", "c", "D", ""]
    ABCD = ["A", "B", "C", "D"]
    ABCD_ = ["A", "B", "C", "D", ""]
    aBcD = ["a", "B", "c", "D"]
    aBcD_ = ["a", "B", "c", "D", ""]

    assert provider.paths_match(None, None)
    assert not provider.paths_match(None, s1)

    if provider.case_sensitive:
        assert provider.paths_match(s1, s2)
        assert provider.paths_match(s1.join(abcd), s2.join(abcd_))
        assert not provider.paths_match(s1.join(abcd_), s2.join(abcD))
    else:  # case-insensitive
        assert provider.paths_match(s1, s2)
        assert provider.paths_match(s1.join(ABCD_), s2.join(aBcD_))
        assert provider.paths_match(s1.join(abcd_), s2.join(aBcD))
        assert provider.paths_match(s1, s2, True)
        # for_display=True must match case for the leaf path node
        assert provider.paths_match(s1.join(ABCD), s2.join(abcD_), for_display=True)
        assert provider.paths_match(s1.join(abcd), s2.join(abcd_), for_display=True)
        assert not provider.paths_match(s1.join(aBcD_), s2.join(abcd), for_display=True)
