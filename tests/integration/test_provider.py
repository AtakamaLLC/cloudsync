import os
import logging
import pytest
from io import BytesIO
from unittest.mock import patch

import cloudsync

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError, CloudFileExistsError
from tests.fixtures.mock_provider import Provider, MockProvider
from cloudsync.runnable import time_helper

from cloudsync.providers import GDriveProvider, DropboxProvider

log = logging.getLogger(__name__)

def gdrive(gdrive_creds):
    if gdrive_creds:
        test_root = "/" + os.urandom(16).hex()
        prov = GDriveProvider(test_root)
        prov.connect(gdrive_creds)
        prov.event_timeout = 60
        prov.event_sleep = 2
        return prov
    else:
        return None

def dropbox(dropbox_creds):
    if dropbox_creds:
        test_root = "/" + os.urandom(16).hex()
        prov = DropboxProvider(test_root)
        prov.connect(dropbox_creds)
        prov.event_timeout = 20
        prov.event_sleep = 2
        return prov
    else:
        return None

@pytest.fixture
def mock():
    ret = MockProvider("/")
    ret.event_timeout = 0
    ret.event_sleep = 0
    return ret


@pytest.fixture(params=['gdrive', 'dropbox', 'mock'])
def provider(request, gdrive_creds, dropbox_creds, mock):
    if request.param == 'gdrive':
        prov = gdrive(gdrive_creds)
    elif request.param == 'dropbox':
        prov = dropbox(dropbox_creds)
    elif request.param == 'mock':
        prov = mock

    if not prov:
        pytest.skip("unsupported provider")

    prov.test_files = []

    def temp_name(name="tmp", *, folder=None):
        fname = prov.join((folder or prov.sync_root, os.urandom(16).hex() + "." + name))
        prov.test_files.append(fname)
        return fname

    # add a provider-specific temp name generator
    prov.temp_name = temp_name

    def events_poll(timeout=prov.event_timeout):
        if timeout == 0:
            yield from prov.events()
            return

        for _ in time_helper(timeout, sleep=prov.event_sleep, multiply=2):
            got = False
            for e in prov.events():
                yield e
                got = True
            if got:
                break

    prov.events_poll = events_poll

    yield prov

    # remove everything in the sync_root
    info = prov.info_path(prov.sync_root)
    if info:
        for info in prov.listdir(info.oid):
            prov.delete(info.oid)

    info = prov.info_path(prov.sync_root)
    if info:
        prov.delete(info.oid)

def test_join(mock):
    assert "/a/b/c" == mock.join(("a", "b", "c"))
    assert "/a/c" == mock.join(("a", None, "c"))
    assert "/a/b/c" == mock.join(("/a", "/b", "/c"))
    assert "/a/c" == mock.join(("a", "/", "c"))

def test_connect(provider):
    assert provider.connected

def test_create_upload_download(util, provider):
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


def test_rename(util, provider: Provider):
    # TODO: test that renaming the parent folder renames the children
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    dest = provider.temp_name("dest")

    info1 = provider.create(dest, data())

    dest2 = provider.temp_name("dest2")

    provider.rename(info1.oid, dest2)

    assert provider.exists_path(dest2)
    assert not provider.exists_path(dest)


def test_mkdir(util, provider: Provider):
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
        info1 = provider.create(dest, data())
    assert provider.exists_path(dest)
    log.debug("folder %s exists", dest)
    info1 = provider.create(sub_f, data())



def test_walk(util, provider: Provider):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")
    info = provider.create(dest, temp)
    assert not provider.walked

    got_event = False
    for e in provider.walk():
        got_event = True
        if e is None:
            break
        if e.otype == cloudsync.DIRECTORY:
            continue
        assert e.oid == info.oid
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert path == dest
        assert e.mtime
        assert e.exists

    assert provider.walked
    assert got_event


def check_event_path(event: Event, provider: Provider, target_path):
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


def test_event_basic(util, provider: Provider):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events_poll(timeout=min(provider.event_timeout,1)):
        log.debug("event %s", e)

    info1 = provider.create(dest, temp)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    event_count = 0
    for e in provider.events_poll():
        log.debug("event %s", e)
        # you might get events for the root folder here or other setup stuff
        if not e.path or e.path == dest:
            event_count += 1
            received_event = e

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


def test_api_failure(provider):
    # assert that the cloud
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    def side_effect(*a, **k):
        if a or k:
            pass
        raise CloudTemporaryError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        with pytest.raises(CloudTemporaryError):
            provider.exists_path("/notexists")


def test_file_not_found(provider):
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    # provider.temp_name = lambda x: "/" + x  # TODO: fix this when we replace the mock fixture with the provider fixture
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    test_path_deleted = provider.temp_name("dest1")  # Created, then deleted
    info1 = provider.create(test_path_deleted, data())
    test_oid_deleted = info1.oid
    provider.delete(test_oid_deleted)

    test_path_made_up = provider.temp_name("dest2")  # Never created
    test_oid_made_up = "never created"
    # TODO: consider mocking info_path to always return None, and then call all the provider methods
    #  to see if they are handling the None, and not raising exceptions other than FNF

    # Tests:
    #   exists_path
    #       returns false, does not raise
    assert provider.exists_path(test_path_deleted) is False
    assert provider.exists_path(test_path_made_up) is False

    #   exists_oid
    #       returns false, does not raise
    assert provider.exists_oid(test_oid_deleted) is False
    assert provider.exists_oid(test_oid_made_up) is False

    #   info_path
    #       deleted file returns None
    #       never existed file returns None
    assert provider.info_path(test_path_deleted) is None
    assert provider.info_path(test_path_made_up) is None

    #   info_oid
    #       deleted file returns None
    #       never existed file returns None
    assert provider.info_oid(test_oid_deleted) is None
    assert provider.info_oid(test_oid_made_up) is None

    #   hash_oid
    #       deleted file returns None
    #       never existed file returns None
    if getattr(provider, "hash_oid", False): # TODO implement hash_oid in gdrive, then don't have this be conditional
        assert provider.hash_oid(test_oid_deleted) is None
        assert provider.hash_oid(test_oid_made_up) is None

    #   upload
    #       to a deleted file raises FNF
    #       to a made up oid raises FNF
    # TODO: uploading to a deleted file might not raise an FNF, it might just untrash the file
    try:
        provider.upload(test_oid_deleted, data())
        assert provider.exists_path(test_path_deleted) is True
        re_delete = True
    except CloudFileNotFoundError:
        re_delete = False
        pass
    
    if re_delete:
        provider.delete(test_oid_deleted)

    with pytest.raises(CloudFileNotFoundError):
        provider.upload(test_oid_made_up, data())

    #   create
    #       to a non-existent folder, conditionally raises FNF
    if not provider.auto_vivify_parent_folders:
        with pytest.raises(CloudFileNotFoundError):
            provider.create("/nonexistentfolder/junk", data())

    #   download
    #       on a deleted oid raises FNF
    #       on a made up oid raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_oid_deleted, data())
    with pytest.raises(CloudFileNotFoundError):
        provider.download(test_oid_made_up, data())

    #   rename
    #       from a deleted oid raises FNF
    #       from a made up oid raises FNF
    #       to a non-existent folder raises [something], conditionally
    #       check the rename source to see if there are others
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_oid_deleted, test_path_deleted)
    with pytest.raises(CloudFileNotFoundError):
        provider.rename(test_oid_made_up, test_path_made_up)

    #   mkdir
    #       to a non-existent folder raises [something], conditionally
    if not provider.auto_vivify_parent_folders:
        with pytest.raises(CloudFileNotFoundError):
            provider.mkdir("/nonexistentfolder/junk")

    #   delete
    #       on a deleted oid does not raise
    #       on a made up oid does not raise
    provider.delete(test_oid_deleted)
    provider.delete(test_oid_made_up)

    #   listdir
    #       raises FNF
    with pytest.raises(CloudFileNotFoundError):
        provider.listdir(test_path_deleted)
    with pytest.raises(CloudFileNotFoundError):
        provider.listdir(test_path_made_up)

    # Google drive raises FNF when it can't find the root... can we test for that here?


def test_file_exists(provider: Provider):
    # Setup the initial state of the provider ==========================================
    dat = os.urandom(32)

    def data(da=dat):
        return BytesIO(da)

    test_folder = os.urandom(8).hex()
    test_file = provider.temp_name()
    # oid_dir = provider.mkdir(test_folder)
    # info_file = provider.create(test_file, data())
    # Setup the initial state of the provider ==========================================

    # Test that operations on existent file system objects raise CloudExistsError
    # when appropriate, and don't when inappropriate
    # api functions to check for FileExists:
    #   mkdir,
    #       where target path has a parent folder that already exists as a file, raises FEx
    #       where target path exists as a file, raises FEx
    #       where target path exists as a folder, does not raise
    #       creating a file, deleting it, then creating a folder at the same path, should not raise an FEx
    #       creating a folder, deleting it, then creating a folder at the same path, should not raise an FEx
    #   upload,
    #       where target OID is a folder, raises FEx
    #   create,
    #       where target path exists, raises FEx
    #       creating a file, deleting it, then creating a file at the same path, should not raise an FEx
    #       creating a folder, deleting it, then creating a file at the same path, should not raise an FEx
    #       where target path has a parent folder that already exists as a file, raises FEx
    #   rename,
    #       rename over empty folder succeeds
    #       rename over non-empty folder raises FEx
    #       target has a parent folder that already exists as a file, raises FEx
    #       renaming file over a folder, raises FEx
    #       renaming a folder over a file, raises FEx
    #       create a file, delete it, then rename a file to the same path as the deleted, does not raise
    #       create a folder, delete it, then rename file to the same path as the deleted, does not raise
    #       create a file, delete it, then rename a folder to the same path as the deleted, does not raise
    #       create a folder, delete it, then rename folder to the same path as the deleted, does not raise



# TODO: test that renaming A over B replaces B's OID with A's OID, and B's OID is trashed

