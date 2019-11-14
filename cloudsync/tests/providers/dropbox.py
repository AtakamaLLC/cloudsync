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

PORT_RANGE = (52400, 54250)

def dropbox_provider():
    cls = DropboxProvider

    # duck type in testing parameters
    cls.event_timeout = 20          # type: ignore
    cls.event_sleep = 2             # type: ignore
    cls.creds = dropbox_creds()     # type: ignore

    return cls(OAuthConfig(app_id=app_id(), app_secret=app_secret(), port_range=PORT_RANGE))


@pytest.fixture
def cloudsync_provider():
    return dropbox_provider()


def connect_test(want_oauth: bool, creds=None, interrupt=False):
    if creds is None:
        creds = dropbox_creds()
    # if not creds:
    #     pytest.skip('requires dropbox token and client secret')
    if want_oauth:
        creds.pop("key", None)  # triggers oauth to get a new refresh token
    sync_root = "/" + os.urandom(16).hex()
    gd = dropbox_provider()
    try:
        gd.connect(creds)
    except CloudTokenError:
        if not want_oauth:
            raise

        if interrupt:
            import time
            import threading
            threading.Thread(target=lambda: (time.sleep(0.5), gd.interrupt_auth()), daemon=True).start()
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

    return creds


def test_connect():
    connect_test(False)


@pytest.mark.manual
def test_oauth_connect():
    connect_test(True)


@pytest.mark.manual
def test_oauth_interrup():
    with pytest.raises(CloudTokenError):
        connect_test(True, interrupt=True)


@pytest.mark.manual
def test_oauth_connect_given_bad_creds():
    creds = connect_test(True, bad_dropbox_creds())

    creds["key"] += "x"

    with pytest.raises(CloudTokenError):
        connect_test(False, creds)
