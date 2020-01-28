# pylint: disable=protected-access,missing-docstring

import logging

from cloudsync.providers import DropboxProvider

log = logging.getLogger(__name__)


def test_rtmp():
    rt = DropboxProvider._gen_rtmp("filename")
    assert DropboxProvider._is_rtmp(rt)
    assert not DropboxProvider._is_rtmp(".-(2304987239048234908239048")
