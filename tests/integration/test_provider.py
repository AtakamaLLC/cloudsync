import os
import pytest
from io import BytesIO
from unittest.mock import patch

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError
from tests.fixtures.mock_provider import Provider, MockProvider

from cloudsync.providers import GDriveProvider

@pytest.fixture
def gdrive(gdrive_creds):
    prov = GDriveProvider()
    prov.connect(gdrive_creds)
    return prov

@pytest.fixture
def dropbox():
    return None


@pytest.fixture
def mock():
    return MockProvider()


@pytest.fixture(params=['gdrive', 'dropbox', 'mock'])
def provider(request, gdrive, dropbox, mock):
    if request.param in ('dropbox'):
        pytest.skip("unsupported configuration")
    prov = {'gdrive': gdrive, 'dropbox': dropbox, 'mock': mock}[request.param]

    prov.test_files = []

    prov.test_root = "/" + os.urandom(16).hex()

    prov.mkdir(prov.test_root)

    def temp_name(name="tmp", folder=None):
        fname = prov.join((prov.test_root, folder, os.urandom(16).hex() + "." +name))
        prov.test_files.append(fname)
        return fname

    # add a provider-specific temp name generator
    prov.temp_name = temp_name

    yield prov

    for name in prov.test_files:
        info = prov.info_path(name)
        if info and info.oid:
            prov.delete(info.oid)

    info = prov.info_path(prov.test_root)
    for info in prov.listdir(info.oid):
        prov.delete(info.oid)

    info = prov.info_path(prov.test_root)
    prov.delete(info.oid)

def test_connect(provider):
    assert provider.connected

def test_create_upload_download(util, provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    hash0 = provider.hash_data(data())

    dest = provider.temp_name("dest")

    info1 = provider.create(dest, data())

    info2 = provider.upload(info1.oid, data())

    assert info1.oid == info2.oid
    assert info1.hash == hash0
    assert info1.hash == info2.hash

    assert provider.exists_path(dest)

    dest = BytesIO()
    provider.download(info2.oid, dest)

    dest.seek(0)
    assert info1.hash == provider.hash_data(dest)


def test_rename(util, provider: Provider):
    # TODO: test that renaming the parent folder renames the children
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    hash0 = provider.hash_data(data())

    dest = provider.temp_name("dest")

    info1 = provider.create(dest, data())

    dest2 = provider.temp_name("dest2")

    provider.rename(info1.oid, dest2)

    assert provider.exists_path(dest2)
    assert not provider.exists_path(dest)


@pytest.mark.skip(reason="not ready yet")
def test_mkdir(util, provider: Provider):
    assert False


def test_walk(util, mock: Provider):
    provider = mock
    temp = BytesIO(os.urandom(32))
    info = provider.create("/dest", temp)
    assert not provider.walked

    got_event = False
    for e in provider.walk():
        got_event = True
        if e is None:
            break
        assert e.oid == info.oid
        path = e.path
        if path is None:
            path = provider.info_oid(e.oid).path
        assert path == "/dest"
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


def test_event_basic(util, mock: Provider):
    provider = mock
    for e in provider.events(timeout=0):
        assert False, "Should not have gotten events, instead got %s" % e

    temp = BytesIO(os.urandom(32))
    info1 = provider.create("/dest", temp)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    event_count = 0
    for e in provider.events(timeout=0):
        if e is None:
            break
        received_event = e
        event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        path = provider.info_oid(received_event.oid).path
    assert path == "/dest"
    assert received_event.mtime
    assert received_event.exists
    provider.delete(oid=received_event.oid)
    with pytest.raises(CloudFileNotFoundError):
        provider.delete(oid=received_event.oid)

    received_event = None
    event_count = 0
    for e in provider.events(timeout=0):
        if e is None:
            break
        received_event = e
        event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        try:
            path = provider.info_oid(received_event.oid).path
            assert path == "/dest"
        except CloudFileNotFoundError:
            if received_event.exists:
                raise
    assert received_event.mtime
    assert not received_event.exists


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


def test_file_not_found(mock: MockProvider):
    provider = mock
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    provider.temp_name = lambda x: "/" + x  # TODO: fix this when we replace the mock fixture with the provider fixture
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
    assert provider.hash_oid(test_oid_deleted) is None
    assert provider.hash_oid(test_oid_made_up) is None

    #   upload
    #       to a deleted file raises FNF
    #       to a made up oid raises FNF
    # TODO: uploading to a deleted file might not raise an FNF, it might just untrash the file
    with pytest.raises(CloudFileNotFoundError):
        provider.upload(test_oid_deleted, data())
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

    #   check for other places in the code where FNF is raised and test those
    #
    #


def test_file_exists(provider):
    # Test that operations on existent file system objects raise CloudExistsError
    # when appropriate, and don't when inappropriate
    # api functions to check for FileExists:
    #   mkdir, where target OID is a file, raises FEx
    #   upload,
    #       where target OID is a folder, raises FEx
    #   create,
    #       where target path exists, raises FEx
    #       creating a folder, deleting it, then creating a file at the same path, should not raise an FEx
    #   rename,
    #       should raise FEx when the target of the rename already exists, conditionally
    #       raises FEx (always) if the target of the rename exists and is not the same type as the source obj

    pass


