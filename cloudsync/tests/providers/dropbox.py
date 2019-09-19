import os
import random

import pytest


from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.providers.dropbox import DropboxProvider
from cloudsync.oauth_config import OAuthConfig


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
    token_set = os.environ.get("DROPBOX_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "key": 'im a bad bad key',
    }
    return creds


def dropbox_provider():

    cls = DropboxProvider

    # duck type in testing parameters
    cls.event_timeout = 20          # type: ignore
    cls.event_sleep = 2             # type: ignore
    cls.creds = dropbox_creds()     # type: ignore
    return cls()


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
    gd = DropboxProvider()
    gd.connect(creds)
    assert gd.client
    quota = gd.get_quota()
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
    api_key = connect_test(True, bad_dropbox_creds())  # Allow this one
    bad_api_key = "x" + api_key[1:]
    with pytest.raises(CloudTokenError):
        connect_test(False, {"key": bad_api_key})  # Reject this one
