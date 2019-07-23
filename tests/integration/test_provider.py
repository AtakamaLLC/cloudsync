import os
import pytest
from io import BytesIO
from unittest.mock import patch

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError
from tests.fixtures.mock_provider import Provider, MockProvider


@pytest.fixture
def gdrive():
    return None


@pytest.fixture
def dropbox():
    return None


@pytest.fixture
def mock():
    return MockProvider()


@pytest.fixture(params=['gdrive', 'dropbox', 'mock'])
def provider(request, gdrive, dropbox, mock):
    if request.param in ('gdrive', 'dropbox'):
        pytest.skip("unsupported configuration")
    return {'gdrive': gdrive, 'dropbox': dropbox, 'mock': mock}[request.param]


def test_connect(provider):
    assert provider.connected


def test_create_upload_download(util, provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    hash0 = provider.hash_data(data())

    info1 = provider.create("/dest", data())

    info2 = provider.upload(info1.oid, data())

    assert info1.oid == info2.oid
    assert info1.hash == hash0
    assert info1.hash == info2.hash

    assert provider.exists_path("/dest")

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

    info1 = provider.create("/dest", data())

    provider.rename(info1.oid, "/dest2")

    assert provider.exists_path("/dest2")
    assert not provider.exists_path("/dest")


@pytest.mark.skip(reason="not ready yet")
def test_mkdir(util, provider: Provider):
    assert False


def test_walk(util, provider: Provider):
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


def test_event_basic(util, provider: Provider):
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
        raise CloudTemporaryError("fake disconnect")

    with patch.object(provider, "_api", side_effect=side_effect):
        with pytest.raises(CloudTemporaryError):
            provider.exists_path("/notexists")


def test_file_not_found(provider):
    # Test that operations on nonexistent file system objects raise CloudFileNotFoundError
    # when appropriate, and don't when inappropriate
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    test_path1 = "/dest1"  # Created, then deleted
    info1 = provider.create(test_path1, data())
    test_oid1 = info1.oid
    provider.delete(test_oid1)

    test_path2 = "/dest2"  # Never created
    test_oid2 = "never created"
    # TODO: consider mocking info_path to always return None, and then call all the provider methods
    #  to see if they are handling the None, and not raising exceptions other than FNF

    # Tests:
    #   exists_path
    #       returns false, does not raise
    assert provider.exists_path(test_path1) is False
    assert provider.exists_path(test_path2) is False

    #   exists_oid
    #       returns false, does not raise
    assert provider.exists_oid(test_oid1) is False
    assert provider.exists_oid(test_oid2) is False

    #   info_path
    #       deleted file returns None
    #       never existed file returns None
    #           handling the None correctly
    assert provider.info_path(test_path)


    #   info_id
    #       deleted file returns None
    #       never existed file returns None
    #       maybe consider mocking this to always return None, and then call all the other methods to see if they are
    #           handling the None correctly
    #   upload
    #       to a made up oid
    #   create
    #       to a non-existent folder, conditionally
    #   download
    #       on a deleted oid raises FNF
    #       on a made up oid raises FNF
    #   rename
    #       from a deleted oid raises FNF
    #       from a made up oid raises FNF
    #       to a non-existent folder raises [something], conditionally
    #       check the rename source to see if there are others
    #   mkdir
    #       to a non-existent folder raises [something], conditionally
    #   delete
    #       on a deleted oid does not raise
    #       on a made up oid does not raise
    #   hash_oid
    #       get rid of hash oid entirely from the provider class
    #   listdir
    #       raises FNF
    #   check for other places in the code where FNF is raised and test those
    #
    #
    pass


def test_file_exists(provider):
    # Test that operations on existent file system objects raise CloudExistsError
    # when appropriate, and don't when inappropriate
    # api functions to check for FileExists:
    #   mkdir should not raise FEx
    #   upload, should not raise FEx
    #   create, should raise FEx
    #   rename, should raise FEx when the target of the rename already exists
    pass


