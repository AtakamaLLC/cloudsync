import os
import random

import pytest


from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.providers.dropbox import DropboxProvider
from cloudsync.oauth import OAuthConfig


def dropbox_creds():
    token_set = os.environ.get("DROPBOX_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "key": tokens[random.randrange(0, len(tokens))],
    }

    return creds

def bad_dropbox_creds():
    creds = {
        "key": 'im a bad bad key',
    }

    return creds

def app_id():
    return os.environ.get("DROPBOX_APP_ID", None)

def app_secret():
    return os.environ.get("DROPBOX_APP_SECRET", None)

def dropbox_provider():
    cls = DropboxProvider

    # duck type in testing parameters
    cls.event_timeout = 20          # type: ignore
    cls.event_sleep = 2             # type: ignore
    cls.creds = dropbox_creds()     # type: ignore

    return cls(app_id=app_id(), app_secret=app_secret())


@pytest.fixture
def cloudsync_provider():
    return dropbox_provider()


def connect_test(want_oauth: bool, creds=None):
    if creds is None:
        creds = dropbox_creds()
    # if not creds:
    #     pytest.skip('requires dropbox token and client secret')
    if want_oauth:
        creds.pop("key", None)  # triggers oauth to get a new refresh token
    sync_root = "/" + os.urandom(16).hex()
    gd = DropboxProvider(app_id=app_id(), app_secret=app_secret())
    try:
        gd.connect(creds)
    except CloudTokenError:
        if not want_oauth:
            raise
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
    return gd.api_key


def test_connect():
    connect_test(False)


@pytest.mark.manual
def test_oauth_connect():
    connect_test(True)


@pytest.mark.manual
def test_oauth_connect_given_bad_creds():
    api_key = connect_test(True, bad_dropbox_creds())

    bad_api_key = "x" + api_key[1:]

    with pytest.raises(CloudTokenError):
        connect_test(False, {"key": bad_api_key})
