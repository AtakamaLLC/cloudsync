import os
import logging
import pytest
from io import BytesIO
from unittest.mock import patch

from cloudsync import Event, CloudFileNotFoundError, CloudTemporaryError
from tests.fixtures.mock_provider import Provider, MockProvider

from cloudsync.providers import GDriveProvider

log = logging.getLogger(__name__)

def gdrive(gdrive_creds):
    if gdrive_creds:
        test_root = "/" + os.urandom(16).hex()
        prov = GDriveProvider(test_root)
        prov.connect(gdrive_creds)
        prov.event_timeout = 30
        return prov
    else:
        return None

def dropbox():
    return None

@pytest.fixture
def mock():
    ret = MockProvider("/")
    ret.event_timeout = 0
    return ret


@pytest.fixture(params=['gdrive', 'dropbox', 'mock'])
def provider(request, gdrive_creds, mock):
    if request.param in ('dropbox'):
        pytest.skip("unsupported configuration")

    if request.param == 'gdrive':
        prov = gdrive(gdrive_creds)
    elif request.param == 'dropbox':
        prov = dropbox()
    elif request.param == 'mock':
        prov = mock

    if not prov:
        pytest.skip("unsupported provider")

    prov.test_files = []

    def temp_name(name="tmp", folder=None):
        fname = prov.join((prov.sync_root, folder, os.urandom(16).hex() + "." +name))
        prov.test_files.append(fname)
        return fname

    # add a provider-specific temp name generator
    prov.temp_name = temp_name

    yield prov

    # remove everything in the sync_root
    info = prov.info_path(prov.sync_root)
    if info:
        for info in prov.listdir(info.oid):
            prov.delete(info.oid)

    info = prov.info_path(prov.sync_root)
    if info:
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


def test_event_basic(util, provider: Provider):
    temp = BytesIO(os.urandom(32))
    dest = provider.temp_name("dest")

    # just get the cursor going
    for e in provider.events(timeout=min(provider.event_timeout,1)):
        log.debug("event %s", e)

    info1 = provider.create(dest, temp)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    event_count = 0
    for e in provider.events(timeout=provider.event_timeout):
        log.debug("event %s", e)
        received_event = e
        event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        path = provider.info_oid(received_event.oid).path
    assert path == dest
    assert received_event.mtime
    assert received_event.exists
    provider.delete(oid=received_event.oid)
    with pytest.raises(CloudFileNotFoundError):
        provider.delete(oid=received_event.oid)

    received_event = None
    event_count = 0
    for e in provider.events(timeout=provider.event_timeout):
        log.debug("event %s", e)
        received_event = e
        event_count += 1

    assert event_count == 1
    assert received_event is not None
    assert received_event.oid
    path = received_event.path
    if path is None:
        try:
            path = provider.info_oid(received_event.oid).path
            assert path == dest
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
