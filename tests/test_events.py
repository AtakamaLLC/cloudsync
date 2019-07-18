import pytest

from pycloud import EventManager

@pytest.fixture
def mock_gdrive():
    return 'a'

@pytest.fixture
def mock_dropbox():
    return 'b'

@pytest.fixture(params=['gdrive', 'dropbox'])
def provider(request, gdrive, dropbox):
    return {'gdrive': mock_gdrive, 'b': mock_dropbox}[request.param]

@pytest.fixture
def env():
    return None

def test_event_basic(env, manager):
    temp = env.temp_file(fill_bytes=32)
    cloud_id1, hash1 = provider.upload(temp, "/dest")

    manager.sync
    for e in .events(timeout=1):
        if e is None:
            break

        assert e.path = "/dest"
        assert e.cloud_id
        assert e.mtime
        assert e.exists
        assert e.source = Event.REMOTE

    provider.delete(cloud_id=e.cloud_id)

    with pytest.raises(CloudFileNotFoundError):
        provider.delete(cloud_id=e.cloud_id)
   
    for e in provider.events(timeout=1):
        if e is None:
            break

        assert e.path = "/dest"
        assert e.cloud_id
        assert e.mtime
        assert not e.exists
        assert e.source = Event.REMOTE

def test_api_failure(provider):
    # assert that the cloud 
    # a) uses an api function
    # b) does not trap CloudTemporaryError's

    with patch.object(provider, "api", side_effect=lambda *a, **k: raise CloudTemporaryError("fake disconned")):
        with pytest.raises(CloudTemporaryError):
            provider.exists("/notexists")


