import os
import time
import logging
import pytest
from io import BytesIO
from unittest.mock import patch
from typing import Union, NamedTuple

import cloudsync

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError, FILE
from cloudsync.tests.fixtures import Provider, mock_provider_instance
from cloudsync.runnable import time_helper
from cloudsync.types import OInfo
from cloudsync.providers import GDriveProvider, DropboxProvider

log = logging.getLogger(__name__)


ProviderMixin = Union[Provider, "ProviderHelper"]


class ProviderHelper(Provider):
    def __init__(self, prov):
        self.api_retry = True
        self.prov = prov

        # need to copy in all attrs that are defined in the ABC
        self.oid_is_path = prov.oid_is_path
        self.case_sensitive = prov.case_sensitive

        self.test_root = getattr(self.prov, "test_root", None)
        self.event_timeout = getattr(self.prov, "event_timeout", 20)
        self.event_sleep = getattr(self.prov, "event_sleep", 1)
        self.creds = getattr(self.prov, "creds", {})

        self.prov_api_func = self.prov._api
        self.prov._api = lambda *ar, **kw: self.__api_retry(self._api, *ar, **kw)

        self.prov.connect(self.creds)

        if not self.test_root:
            # if the provider class doesn't specify a testing root
            # then just make one up
            self.test_root = "/" + os.urandom(16).hex()
            self.prov.mkdir(self.test_root)

    def _api(self, *ar, **kw):
        return self.prov_api_func(*ar, **kw)

    def __api_retry(self: ProviderMixin, func, *ar, **kw):
        # the cloud providers themselves should *not* have their own backoff logic
        # rather, they should punt rate limit and temp errors to the sync system
        # since we're not testing the sync system here, we need to make our own
        if not self.api_retry:
            return func(*ar, **kw)

        for _ in time_helper(timeout=self.event_timeout, sleep=self.event_sleep, multiply=2):
            try:
                return func(*ar, **kw)
            except CloudTemporaryError:
                log.info("api retry %s %s %s", func, ar, kw)

    # TEST-ROOT WRAPPER

    def __getattr__(self, k):
        return getattr(self.prov, k)

    def events(self):
        for e in self.prov.events():
            if self.__filter_root(e):
                yield e

    def walk(self, path):
        path = self.__add_root(path)
        log.debug("WALK %s", path)
        for e in self.prov.walk(path):
            if self.__filter_root(e):
                yield e

    def download(self, *args, **kwargs):
        return self.__strip_root(self.prov.download(*args, **kwargs))

    def create(self, path, file_like, metadata=None):
        path = self.__add_root(path)
        log.debug("CREATE %s", path)
        return self.__strip_root(self.prov.create(path, file_like, metadata))

    def upload(self, *args, **kwargs):
        return self.__strip_root(self.prov.upload(*args, **kwargs))

    def rename(self, oid, path):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.rename(oid, path))

    def mkdir(self, path):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.mkdir(path))

    def delete(self, *args, **kwargs):
        return self.__strip_root(self.prov.delete(*args, **kwargs))

    def exists_oid(self, oid):
        return self.prov.exists_oid(oid)

    def exists_path(self, path):
        path = self.__add_root(path)
        return self.prov.exists_path(path)

    def info_path(self, path):
        path = self.__add_root(path)
        return self.__strip_root(self.prov.info_path(path))

    def info_oid(self, oid):
        return self.__strip_root(self.prov.info_oid(oid))

    def listdir(self, oid):
        for e in self.prov.listdir(oid):
            if self.__filter_root(e):
                yield e

    def __add_root(self, path):
        return self.join(self.test_root, path)

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

            if not raw_path.startswith(self.test_root):
                return False

            self.__strip_root(obj)

        return True

    def __strip_root(self, obj):
        if hasattr(obj, "path"):
            path = obj.path
            if path:
                assert path.startswith(self.test_root)
                path = obj.path[len(self.test_root):]
                if not path.startswith("/"):
                    path = "/" + path
                obj.path = path
        return obj
    # HELPERS

    def temp_name(self: ProviderMixin, name="tmp", *, folder=None):
        fname = self.join(folder or "/", os.urandom(16).hex() + "." + name)
        return fname

    def events_poll(self: ProviderMixin, timeout=None, until=None):
        if timeout is None:
            timeout = self.event_timeout

        if timeout == 0:
            yield from self.events()
            return

        for _ in time_helper(timeout, sleep=self.event_sleep, multiply=2):
            got = False
            for e in self.events():
                yield e
                got = True
            if not until and got:
                break
            elif until and until():
                break

    def __cleanup(self: ProviderMixin, oid):
        try:
            for info in self.prov.listdir(oid):
                if info.otype == FILE:
                    log.debug("cleaning %s", info)
                    self.delete(info.oid)
                else:
                    self.__cleanup(info.oid)
                    log.debug("cleaning %s", info)
                    self.delete(info.oid)
        except CloudFileNotFoundError:
            pass

    def test_cleanup(self: ProviderMixin, timeout=None, until=None):
        info = self.prov.info_path(self.test_root)
        self.__cleanup(info.oid)

        info = self.prov.info_path(self.test_root)
        if info:
            try:
                log.debug("cleaning %s", info)
                self.delete(info.oid)
            except CloudFileExistsError:
                # deleting the root might now be supported
                pass


def mixin_provider(prov):
    assert prov
    assert isinstance(prov, Provider)

    prov = ProviderHelper(prov)

    yield prov

    prov.test_cleanup()


@pytest.fixture
def provider_params():
    return None


class ProviderConfig:
    def __init__(self, name, param=(), param_id=None):
        if param_id is None:
            param_id = name
        self.name = name
        if name == "mock":
            assert param
        self.param = param
        self.param_id = param_id

    def __repr__(self):
        return "%s(%s)" % (type(self), self.__dict__)


@pytest.fixture
def config_provider(request, provider_config):
    try:
        request.raiseerror("foo")
    except Exception as e:
        FixtureLookupError = type(e)

    if provider_config.name == "external":
        # if there's a fixture available, use it
        return request.getfixturevalue("cloudsync_provider")
        # deferring imports to prevent needing deps we don't want to require for everyone
    elif provider_config.name == "mock":
        return mock_provider_instance(*provider_config.param)
    elif provider_config.name == "gdrive":
        from .providers.gdrive import gdrive_provider
        return gdrive_provider()
    elif provider_config.name == "dropbox":
        from .providers.dropbox import dropbox_provider
        return dropbox_provider()
    else:
        assert False, "Must provide a valid --provider name or use the -p <plugin>"


known_providers = ('gdrive', 'external', 'dropbox', 'mock')


def configs_from_name(name):
    provs = []

    if name == "mock":
        provs += [ProviderConfig("mock", (False, True), "mock_oid_cs")]
        provs += [ProviderConfig("mock", (True, True), "mock_path_cs")]
    else:
        provs += [ProviderConfig(name)]

    return provs


def configs_from_keyword(kw):
    provs = []
    # crappy approximation of pytest evaluation routine, because
    false = {}
    for known_prov in known_providers:
        false[known_prov] = False

    for known_prov in known_providers:
        if known_prov == kw or '[' + known_prov + ']' == kw:
            ok = True
        else:
            ids = false.copy()
            ids[known_prov] = True
            try:
                ok = eval(kw, {}, ids)
            except NameError as e:
                ok = False
            except Exception as e:
                log.error("%s %s", type(e), e)
                ok = False
            if type(ok) is list:
                ok = any(ok)
        if ok:
            provs += configs_from_name(known_prov)
    return provs


_registered = False


def pytest_generate_tests(metafunc):
    global _registered
    if not _registered:
        for known_prov in known_providers:
            metafunc.config.addinivalue_line(
                "markers", known_prov
            )
        _registered = True

    if "provider_config" in metafunc.fixturenames:
        provs = []

        for e in metafunc.config.getoption("provider", []):
            for n in e.split(","):
                provs += configs_from_name(n)

        if not provs:
            kw = metafunc.config.getoption("keyword", "")
            if kw:
                provs += configs_from_keyword(kw)

        if not provs:
            provs += configs_from_name("mock")

        ids = [p.param_id for p in provs]
        marks = [pytest.param(p, marks=[getattr(pytest.mark, p.name)]) for p in provs]

        metafunc.parametrize("provider_config", marks, ids=ids)


@pytest.fixture
def provider(config_provider):
    yield from mixin_provider(config_provider)


def test_join(mock_provider):
    assert "/a/b/c" == mock_provider.join("a", "b", "c")
    assert "/a/c" == mock_provider.join("a", None, "c")
    assert "/a/b/c" == mock_provider.join("/a", "/b", "/c")
    assert "/a/c" == mock_provider.join("a", "/", "c")


def test_connect(provider):
    assert provider.connected


def test_create_upload_download(provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")

    info1 = provider.create(dest, data())

    info2 = provider.upload(info1.oid, data())

    assert info1.oid == info2.oid
    assert info1.hash == info2.hash

    assert provider.exists_path(dest)

    dest = BytesIO()
    provider.download(info2.oid, dest)

    dest.seek(0)
    assert dest.getvalue() == dat


def test_rename(provider: ProviderMixin):
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

    provider.rename(folder_oid, folder_name2)

    assert provider.exists_path(file_path2)
    assert not provider.exists_path(file_path1)
    assert provider.exists_path(sub_file_path2)
    assert not provider.exists_path(sub_file_path1)

    if not provider.oid_is_path:
        assert provider.exists_oid(file_info.oid)
        assert provider.exists_oid(sub_file_info.oid)
        assert provider.info_oid(file_info.oid).path == file_path2
        assert provider.info_oid(sub_file_info.oid).path == sub_file_path2
    else:
        assert not provider.exists_oid(file_info.oid)
        assert not provider.exists_oid(sub_file_info.oid)


def test_mkdir(provider: ProviderMixin):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)
    dest = provider.temp_name("dest")
    provider.mkdir(dest)
    info = provider.info_path(dest)
    assert info.otype == cloudsync.DIRECTORY
    sub_f = provider.temp_name("dest", folder=dest)
    log.debug("parent = %s, sub = %s", dest, sub_f)
    with pytest.raises(CloudFileExistsError):
        provider.create(dest, data(), None)
    assert provider.exists_path(dest)
    log.debug("folder %s exists", dest)
    provider.create(sub_f, data(), None)


def test_walk(provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    info = provider.create(dest, temp, None)

    got_event = False
    for e in provider.walk("/"):
        if e.otype == cloudsync.DIRECTORY:
            continue
        log.debug("WALK %s", e)
        assert e.oid == info.oid
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert path == dest
        assert e.mtime
        assert e.exists
        got_event = True

    assert got_event


def check_event_path(event: Event, provider: ProviderMixin, target_path):
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


def test_event_basic(provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_sleep, 1)):
        log.debug("event %s", e)

    wait_sleep_cycles = 10

    info1 = provider.create(dest, temp, None)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    event_count = 0
    done = False
    waiting = None
    wait_secs = min(provider.event_sleep * wait_sleep_cycles, 2)
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
                event_count += 1

            log.debug("%s vs %s", e.path, dest)

            if e.path == dest and not waiting:
                waiting = time.monotonic() + wait_secs

        if waiting and time.monotonic() > waiting:
            # wait for extra events up to 10 sleep cycles, or 2 seconds
            done = True

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        path = provider.info_oid(received_event.oid).path
    assert path == dest
    assert received_event.mtime
    assert received_event.exists
    deleted_oid = received_event.oid
    provider.delete(oid=deleted_oid)
    provider.delete(oid=deleted_oid)  # Tests that deleting a non-existing file does not raise a FNFE

    received_event = None
    event_count = 0
    for e in provider.events_poll():
        log.debug("event %s", e)
        if not e.exists or path in e.path:
            received_event = e
            event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    assert not received_event.exists
    if received_event.path is not None:
        assert received_event.path == dest
    assert received_event.oid == deleted_oid
    assert received_event.mtime


def test_event_del_create(provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    temp2 = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_sleep * 10, 1)):
        log.debug("event %s", e)

    info1 = provider.create(dest, temp)
    provider.delete(info1.oid)
    provider.create(dest, temp2)

    last_event = None
    saw_delete = False
    done = False
    for e in provider.events_poll(provider.event_timeout * 2, until=lambda: done):
        log.debug("event %s", e)
        # you might get events for the root folder here or other setup stuff
        path = e.path
        if not e.path:
            info = provider.info_oid(e.oid)
            if info:
                path = info.path

        if path == dest or e.exists is False:
            last_event = e

            if e.exists is True and saw_delete:
                log.debug("done, we saw the delete and got a create after")
                done = True

            if e.exists is False:
                saw_delete = True

    # the important thing is that we always get a create after the delete event
    assert last_event
    assert last_event.exists is True


def test_event_rename(provider: ProviderMixin):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    dest2 = provider.temp_name("dest")
    dest3 = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_sleep * 10, 1)):
        log.debug("event %s", e)

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
    done = False
    for e in provider.events_poll(provider.event_timeout * 2, until=lambda: done):
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
                second_to_last = True
            if path == dest3 and (second_to_last or not provider.oid_is_path):
                done = True
        else:
            done = info1.oid in seen

    if provider.oid_is_path:
        # providers with path based oids need to send intermediate renames accurately and in order
        assert len(seen) > 2
        assert last_event.path == dest3
        assert last_event.prior_oid == oid2
    else:
        # oid based providers just need to let us know something happend to that oid
        assert info1.oid in seen


def test_api_failure(provider):
    # assert that the cloud
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    def side_effect(*a, **k):
        raise CloudTemporaryError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        with patch.object(provider, "api_retry", False):
            with pytest.raises(CloudTemporaryError):
                provider.exists_path("/notexists")


def test_file_not_found(provider: ProviderMixin):
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    test_file_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_file_deleted_info = provider.create(test_file_deleted_path, data(), None)
    test_file_deleted_oid = test_file_deleted_info.oid
    provider.delete(test_file_deleted_oid)

    test_folder_deleted_path = provider.temp_name("dest1")  # Created, then deleted
    test_folder_deleted_oid = provider.mkdir(test_folder_deleted_path)
    provider.delete(test_folder_deleted_oid)

    test_path_made_up = provider.temp_name("dest2")  # Never created
    test_oid_made_up = "never created"
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
    #       from a made up oid raises FNF
    #       to a non-existent folder raises [something], conditionally
    #       to a previously deleted folder raises
    #       check the rename source to see if there are others
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_file_deleted_oid, test_file_deleted_path)
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_folder_deleted_oid, test_folder_deleted_path)
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_oid_made_up, test_path_made_up)

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


def test_file_exists(provider: ProviderMixin):
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
    _, oid = create_folder()
    with pytest.raises(CloudFileExistsError):
        provider.upload(oid, data(), None)

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
    assert oid1 != oid or provider.oid_is_path

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

    #   rename: renaming a folder over a file, raises FEx
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


# TODO: test that renaming A over B replaces B's OID with A's OID, and B's OID is trashed


def test_listdir(provider: ProviderMixin):
    outer = provider.temp_name()
    root = provider.dirname(outer)
    temp_name = provider.is_subpath(root, outer)

    outer_oid_rm = provider.mkdir(outer)
    assert [] == list(provider.listdir(outer_oid_rm))
    provider.delete(outer_oid_rm)

    outer_oid = provider.mkdir(outer)

    assert provider.exists_path(outer)
    assert provider.exists_oid(outer_oid)
    inner = outer + temp_name
    inner_oid = provider.mkdir(inner)
    assert provider.exists_oid(inner_oid)
    provider.create(outer + "/file1", BytesIO(b"hello"))
    provider.create(outer + "/file2", BytesIO(b"there"))
    provider.create(inner + "/file3", BytesIO(b"world"))
    contents = [x.name for x in provider.listdir(outer_oid)]
    assert len(contents) == 3
    expected = ["file1", "file2", temp_name[1:]]
    assert contents.sort() == expected.sort()


def test_upload_to_a_path(provider: ProviderMixin):
    temp_name = provider.temp_name()
    provider.create(temp_name, BytesIO(b"test"))
    # test uploading to a path instead of an OID. should raise something
    # This test will need to flag off whether the provider uses paths as OIDs or not
    with pytest.raises(Exception):
        provider.upload(temp_name, BytesIO(b"test2"))


def test_delete_doesnt_cross_oids(provider: ProviderMixin):
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
