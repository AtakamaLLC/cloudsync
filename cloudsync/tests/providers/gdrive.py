import os
import random
import pytest
from cloudsync.exceptions import CloudFileNotFoundError, CloudTokenError
from cloudsync.providers.gdrive import GDriveProvider


# move this to provider ci_creds() function?
def gdrive_creds():
    token_set = os.environ.get("GDRIVE_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh_token": tokens[random.randrange(0, len(tokens))],
    }

    return creds


def on_success(auth_dict=None):
    assert auth_dict is not None and isinstance(auth_dict, dict)


def app_id():
    return os.environ.get("GDRIVE_APP_ID", None)

def app_secret():
    return os.environ.get("GDRIVE_APP_SECRET", None)

def gdrive_provider():

    cls = GDriveProvider

    # duck type in testing parameters
    cls.event_timeout = 60                  # type: ignore
    cls.event_sleep = 2                     # type: ignore
    cls.creds = gdrive_creds()              # type: ignore

    return cls(app_id=app_id(), app_secret=app_secret())

@pytest.fixture
def cloudsync_provider():
    gdrive_provider()


