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


def dropbox_provider():
    cls = DropboxProvider
    cls.event_timeout = 20
    cls.event_sleep = 2
    cls.creds = dropbox_creds()
    return cls()


@pytest.fixture
def cloudsync_provider():
    return dropbox_provider()


def test_connect():
    creds = dropbox_creds()
    if not creds:
        pytest.skip('requires dropbox token and client secret')
    sync_root = "/" + os.urandom(16).hex()
    gd = DropboxProvider(sync_root)
    gd.connect(creds)
    assert gd.client
    quota = gd.get_quota()
    try:
        info = gd.info_path(sync_root)
        if info and info.oid:
            gd.delete(info.oid)
    except CloudFileNotFoundError:
        pass
