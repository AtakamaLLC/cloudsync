import os
import pytest
import random

from cloudsync.providers import OneDriveProvider
from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.oauth import OAuthConfig

def onedrive_creds():
    token_set = os.environ.get("ONEDRIVE_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh": tokens[random.randrange(0, len(tokens))],
        "url": 'https://login.live.com/oauth20_token.srf',
        "access": None,
    }

    return creds


def app_id():
    return os.environ.get("ONEDRIVE_APP_ID", None)


def app_secret():
    return os.environ.get("ONEDRIVE_APP_SECRET", None)

PORT_RANGE = 54200, 54210 
def onedrive_provider():

    cls = OneDriveProvider

    # duck type in testing parameters
    cls.event_timeout = 60                  # type: ignore
    cls.event_sleep = 2                     # type: ignore
    cls.creds = onedrive_creds()              # type: ignore

    config = OAuthConfig(app_id=app_id(), app_secret=app_secret(), port_range=PORT_RANGE, host_name="localhost")
    return cls(config)

