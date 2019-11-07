import os
import pytest
import random

from cloudsync.providers import OneDriveProvider
from cloudsync.exceptions import CloudFileNotFoundError
from cloudsync.oauth import OAuthConfig

def onedrive_creds():
    token_set = os.environ.get("ONEDRIVE_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh_token": tokens[random.randrange(0, len(tokens))],
    }

    return creds


def app_id():
    return os.environ.get("ONEDRIVE_APP_ID", None)


def app_secret():
    return os.environ.get("ONEDRIVE_APP_SECRET", None)


# this seems generic enough now it could use a provider class fixture and be moved to the provider tests

@pytest.mark.manual
def test_oauth_connect():
    sync_root = "/" + os.urandom(16).hex()
    prov = OneDriveProvider(OAuthConfig(app_id=app_id(), app_secret=app_secret()))
    creds = prov.authenticate()
    prov.connect(creds)
    assert prov.client
    prov.get_quota()
    try:
        info = prov.info_path(sync_root)
        if info and info.oid:
            prov.delete(info.oid)
    except CloudFileNotFoundError:
        pass
