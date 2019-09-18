import os
import random
import pytest
from cloudsync.exceptions import CloudFileNotFoundError
from cloudsync.providers.gdrive import GDriveProvider
from cloudsync.oauth_config import OAuthConfig


# move this to provider ci_creds() function?
def gdrive_creds():
    token_set = os.environ.get("GDRIVE_TOKEN")
    cli_sec = os.environ.get("GDRIVE_CLI_SECRET")
    if not token_set or not cli_sec:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh_token": tokens[random.randrange(0, len(tokens))],
        "client_secret": cli_sec,
        "client_id": '433538542924-ehhkb8jn358qbreg865pejbdpjnm31c0.apps.googleusercontent.com',
    }

    return creds


def on_success(auth_dict=None):
    assert auth_dict is not None and isinstance(auth_dict, dict)


def gdrive_provider():
    cls = GDriveProvider

    # duck type in testing parameters
    cls.event_timeout = 60                  # type: ignore
    cls.event_sleep = 2                     # type: ignore
    cls.creds = gdrive_creds()              # type: ignore

    return cls()


@pytest.fixture
def cloudsync_provider():
    gdrive_provider()


def connect_test(want_oauth: bool):
    creds = gdrive_creds()
    if not creds:
        pytest.skip('requires gdrive token and client secret')
    if want_oauth:
        creds.pop("refresh_token", None)  # triggers oauth to get a new refresh token
    sync_root = "/" + os.urandom(16).hex()
    gd = GDriveProvider()
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
