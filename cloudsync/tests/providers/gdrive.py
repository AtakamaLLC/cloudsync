import os
import random
import pytest
from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.providers.gdrive import GDriveProvider


# move this to provider ci_creds() function?
def gdrive_creds():
    token_set = os.environ.get("GDRIVE_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh_token": tokens[random.randrange(0, len(tokens))],
    }

    return creds


def on_success(auth_dict=None):
    assert auth_dict is not None and isinstance(auth_dict, dict)


def app_id():
    return os.environ.get("GDRIVE_APP_ID", None)

def app_secret():
    return os.environ.get("GDRIVE_APP_SECRET", None)

def gdrive_provider():

    cls = GDriveProvider

    # duck type in testing parameters
    cls.event_timeout = 60                  # type: ignore
    cls.event_sleep = 2                     # type: ignore
    cls.creds = gdrive_creds()              # type: ignore

    return cls(app_id=app_id(), app_secret=app_secret())

@pytest.fixture
def cloudsync_provider():
    gdrive_provider()


def connect_test(want_oauth: bool, interrupt=False):
    creds = gdrive_creds()
    if not creds:
        pytest.skip('requires gdrive token')
    if want_oauth:
        creds.pop("refresh_token", None)  # triggers oauth to get a new refresh token
    sync_root = "/" + os.urandom(16).hex()
    gd = GDriveProvider(app_id=app_id(), app_secret=app_secret())

    try:
        gd.connect(creds)
    except CloudTokenError:
        if not want_oauth:
            raise
        if interrupt:
            assert want_oauth
            import time
            import threading
            threading.Thread(target=lambda: (time.sleep(0.5), gd.interrupt_auth()), daemon=True).start()      # type: ignore 
        creds = gd.authenticate()
        gd.connect(creds)

    assert gd.client
    gd.get_quota()
    try:
        info = gd.info_path(sync_root)
        if info and info.oid:
            gd.delete(info.oid)
    except CloudFileNotFoundError:
        pass


def test_connect():
    connect_test(False)


@pytest.mark.manual
def test_oauth_connect():
    connect_test(True)

@pytest.mark.manual
def test_oauth_interrup():
    with pytest.raises(CloudTokenError):
        connect_test(True, interrupt=True)
