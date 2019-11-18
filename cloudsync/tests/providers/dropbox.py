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


