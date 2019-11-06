import os
import pytest


def onedrive_creds():
    token_set = os.environ.get("GDRIVE_TOKEN")
    if not token_set:
        return None

    tokens = token_set.split(",")

    creds = {
        "refresh_token": tokens[random.randrange(0, len(tokens))],
    }

    return creds


def connect_test(want_oauth: bool):
    creds = onedrive_creds()
    if not creds:
        pytest.skip('requires gdrive token')
    if want_oauth:
        creds.pop("refresh_token", None)  # triggers oauth to get a new refresh token
    sync_root = "/" + os.urandom(16).hex()
    gd = GDriveProvider(app_id=app_id(), app_secret=app_secret())
    gd.connect(creds)
    assert gd.client
    gd.get_quota()
    try:
        info = gd.info_path(sync_root)
        if info and info.oid:
            gd.delete(info.oid)
    except CloudFileNotFoundError:
        pass
