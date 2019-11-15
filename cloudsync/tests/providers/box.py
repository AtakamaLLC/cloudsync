import os
import random
import logging
import pytest
from cloudsync.oauth import OAuthConfig

from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.providers.box import BoxProvider


# move this to provider ci_creds() function?
def box_creds():
    token_set = os.environ.get("BOX_TOKEN")
    if not token_set:
        return {}

    tokens = token_set.split("|")

    creds = {
        "jwt_token": tokens[random.randrange(0, len(tokens))],
    }

    return creds


def on_success(auth_dict=None):
    assert auth_dict is not None and isinstance(auth_dict, dict)


def app_id():
    return os.environ.get("BOX_APP_ID", None)


def app_secret():
    return os.environ.get("BOX_APP_SECRET", None)


def box_provider():

    cls = BoxProvider

    # duck type in testing parameters
    cls.event_timeout = 60                  # type: ignore
    cls.event_sleep = 2                     # type: ignore
    cls.creds = box_creds()              # type: ignore

    return cls(OAuthConfig(app_id=app_id(), app_secret=app_secret()))


@pytest.fixture
def cloudsync_provider():
    box_provider()


def connect_test(want_oauth: bool):
    creds = box_creds()
    if want_oauth:
        creds.pop("refresh_token", None)  # triggers oauth to get a new refresh token
    elif not creds:
        pytest.skip('requires box token')
    sync_root = "/" + os.urandom(16).hex()
    box = BoxProvider(OAuthConfig(app_id=app_id(), app_secret=app_secret()))
    try:
        box.connect(creds)
    except CloudTokenError:
        if not want_oauth:
            raise
        creds = box.authenticate()
        logging.error(f'creds are {creds}')
        box.connect(creds)

    assert box.client
    box.get_quota()
    try:
        info = box.info_path(sync_root)
        if info and info.oid:
            box.delete(info.oid)
    except CloudFileNotFoundError:
        pass

def test_connect():
    connect_test(False)


@pytest.mark.manual
def test_oauth_connect():
    connect_test(True)
