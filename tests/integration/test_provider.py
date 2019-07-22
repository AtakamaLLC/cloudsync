import os
from io import BytesIO

import pytest
from unittest.mock import patch

from pycloud import Event, CloudFileNotFoundError, CloudTemporaryError

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

# todo: should work with file-likes rather than path. Should it do it magically?


def test_upload(util, provider):
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


def test_rename(util, provider):
    dat = os.urandom(32)

    def data():
        return BytesIO(dat)

    hash0 = provider.hash_data(data())

    info1 = provider.create("/dest", data())

    provider.rename(info1.oid, "/dest2")

    assert provider.exists_path("/dest2")
    assert not provider.exists_path("/dest")


def test_walk(util, provider: Provider):
    temp = BytesIO(os.urandom(32))
    info = provider.create("/dest", temp)
    assert not provider.walked

    got_event = False
    for e in provider.events(timeout=1):
        got_event = True
        if e is None:
            break
        assert provider.walked
        assert e.path == "/dest"
        assert e.cloud_id == info.cloud_id
        assert e.mtime
        assert e.exists
        assert e.source == Event.REMOTE

    assert got_event


def test_event_basic(util, provider: Provider):
    for e in provider.events(timeout=1):
        if e is None:
            break
        assert False, "no events here!"

    assert provider.walked

    temp = BytesIO(os.urandom(32))
    info1 = provider.create("/dest", temp)
    assert info1 is not None  # TODO: check info1 for more things

    received_event = None
    for e in provider.events(timeout=1):
        if e is None:
            break
        received_event = e

    assert received_event is not None
    assert received_event.path == "/dest"
    assert received_event.cloud_id
    assert received_event.mtime
    assert received_event.exists
    assert received_event.source == Event.REMOTE
    provider.delete(cloud_id=received_event.cloud_id)
    with pytest.raises(CloudFileNotFoundError):
        provider.delete(cloud_id=received_event.cloud_id)

    received_event = None
    for e in provider.events(timeout=1):
        if e is None:
            break
        received_event = e

    assert received_event is not None
    assert received_event.path == "/dest"
    assert received_event.cloud_id
    assert received_event.mtime
    assert not received_event.exists
    assert received_event.source == Event.REMOTE


def test_api_failure(provider):
    # assert that the cloud
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    def side_effect(*a, **k):
        raise CloudTemporaryError("fake disconned")

    with patch.object(provider, "_api", side_effect=side_effect):
        with pytest.raises(CloudTemporaryError):
            provider.exists_path("/notexists")
