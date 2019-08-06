import os
import random

import pytest


from cloudsync.exceptions import CloudFileNotFoundError
from cloudsync.providers.gdrive import GDriveProvider

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


def gdrive_provider():
    cls = GDriveProvider
    cls.event_timeout = 60
    cls.event_sleep = 2
    cls.creds = gdrive_creds()
    return cls()


@pytest.fixture
def cloudsync_provider():
    gdrive_provider()


def test_connect():
    creds = gdrive_creds()
    if not creds:
        pytest.skip('requires gdrive token and client secret')
    sync_root = "/" + os.urandom(16).hex()
    gd = GDriveProvider(sync_root)
    gd.connect(creds)
    assert gd.client
    quota = gd.get_quota()
    try:
        info = gd.info_path(sync_root)
        if info and info.oid:
            gd.delete(info.oid)
    except CloudFileNotFoundError:
        pass
