import pytest

from pycloud import EventManager

@pytest.fixture
def mock_gdrive():
    # return a manager linked to mock-provider gdrive
    return 'a'

@pytest.fixture
def mock_dropbox():
    # return a manager linked to mock-provider gdrive
    return 'b'

@pytest.fixture(params=['gdrive', 'dropbox'])
def manager(request, gdrive, dropbox):
    return {'gdrive': mock_gdrive, 'b': mock_dropbox}[request.param]

@pytest.fixture
def util():
    return None

def test_event_basic(util, manager):
    temp = util.temp_file(fill_bytes=32)
    cloud_id1, hash1 = provider.upload(temp, "/dest")

    # this is normally a blocking function that runs forever
    def done():
        return os.path.exists(local_path)

    # loop the sync until the file is found
    manager.sync(timeout=1, until=done)

    local_path = manager.local_path("/fandango")

    util.fill_bytes(local_path, count=32)

    manager.local_event(path=local_path, exists=True)

    # loop the sync until the file is found
    manager.sync(timeout=1, until=done)

    info = provider.info("/fandango")

    assert info.hash == provider.local_hash(temp)
    assert info.cloud_id
