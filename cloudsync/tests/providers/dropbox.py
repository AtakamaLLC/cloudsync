import os
import random

import pytest


from cloudsync.exceptions import CloudFileNotFoundError
from cloudsync.providers.dropbox import DropboxProvider


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
    cls.event_timeout = 20
    cls.event_sleep = 2
    cls.creds = dropbox_creds()
    return cls()


@pytest.fixture
def cloudsync_provider():
    return dropbox_provider()


def connect_test(want_oauth: bool, use_real_creds: bool):
    if use_real_creds:
        creds = dropbox_creds()
    else:
        creds = bad_dropbox_creds()
    if not creds:
        pytest.skip('requires dropbox token and client secret')
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


def test_connect():
    connect_test(False, True)


@pytest.mark.manual
def test_oauth_connect():
    connect_test(True, True)

@pytest.mark.manual
def test_oauth_connect_given_bad_creds():
    connect_test(False, False)
