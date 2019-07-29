import os
import random

import pytest


from cloudsync.exceptions import CloudFileNotFoundError
from cloudsync.providers.gdrive import GDriveProvider

@pytest.fixture(name="gdrive_creds", scope="session")
def fixture_gdrive_creds():
    token_set = os.environ.get("GDRIVE_TOKEN")
    cli_sec = os.environ.get("GDRIVE_CLI_SECRET")
    if not token_set or not cli_sec:
        return None

    tokens = token_set.split(",")

    creds = {
            "refresh_token" : tokens[random.randrange(0, len(tokens))],
            "client_secret" : cli_sec,
            "client_id" : '433538542924-ehhkb8jn358qbreg865pejbdpjnm31c0.apps.googleusercontent.com',
    }
    
    return creds

def test_connect(gdrive_creds):
    if not gdrive_creds:
        pytest.skip('requires gdrive token and client secret')
    sync_root = "/" + os.urandom(16).hex()
    gd = GDriveProvider(sync_root)
    gd.connect(gdrive_creds)
    assert gd.client
    quota = gd.get_quota()
    try:
        info = gd.info_path(sync_root)
        if info and info.oid:
            gd.delete(info.oid)
    except CloudFileNotFoundError:
        pass
