# pylint: disable=protected-access,missing-docstring

import logging
import os

from typing import Generator

from unittest.mock import patch, Mock

from cloudsync.providers import DropboxProvider

import dropbox

log = logging.getLogger(__name__)


def test_rtmp():
    rt = DropboxProvider._gen_rtmp("filename")
    assert DropboxProvider._is_rtmp(rt)
    assert not DropboxProvider._is_rtmp(".-(2304987239048234908239048")


@patch("cloudsync.providers.dropbox._FolderIterator")
def test_events(fi: Mock):
    db = DropboxProvider()

    chash = os.urandom(32).hex()

    def mock_iterate(*_a, **_kw) -> Generator[dropbox.files.Metadata, None, None]:
        yield dropbox.files.FileMetadata(name="YO.txt", id="id1", path_display="/YO.txt", path_lower="/yo.txt", content_hash=chash)
        tmpname = db._gen_rtmp("TMP")
        yield dropbox.files.FileMetadata(name=tmpname, id="id2", path_display="/" + tmpname, path_lower="/" + tmpname.lower(), content_hash=chash)

    fi.side_effect = mock_iterate

    evs = list(db._events(cursor=None, path="/"))

    ids = {}
    for ev in evs:
        ids[ev.oid] = ev

    assert "id1" in ids
    assert "id2" not in ids

    ev1 = ids["id1"]

    assert ev1.hash == chash
    assert ev1.path == "/YO.txt"
    assert ev1.exists
    assert ev1.mtime > 0

    log.info("evs %s", evs)
