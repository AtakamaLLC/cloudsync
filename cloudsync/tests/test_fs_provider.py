# pylint: disable=protected-access

import os
import logging
import shutil
import time
from unittest.mock import patch

import pytest

from cloudsync.providers import FileSystemProvider
from cloudsync.providers.filesystem import get_hash
from watchdog import events as watchdog_events

log = logging.getLogger(__name__)

@pytest.fixture
def fsp():
    fsp = FileSystemProvider()
    fsp.namespace = fsp._test_namespace
    yield fsp
    shutil.rmtree(fsp.namespace_id)


def test_fast_hash(fsp: FileSystemProvider, tmpdir):
    f = tmpdir / "file"

    f.write(b"hi"*2000)
    h1 = fsp._fast_hash_path(str(f))
    mtime = f.stat().mtime

    #### mtime/data is the same
    with patch("cloudsync.providers.filesystem.get_hash", side_effect=get_hash) as m:
        h2 = fsp._fast_hash_path(str(f))
        print("calls %s", m.mock_calls)
        # get-hash called once, on the subset of data only
        m.assert_called_once()

    assert h1 == h2

    #### mtime changed, so we re-hash
    os.utime(f, (time.time(), time.time()))
    
    with patch("cloudsync.providers.filesystem.get_hash", side_effect=get_hash) as m:
        h2 = fsp._fast_hash_path(str(f))
        print("calls %s", m.mock_calls)
        # get-hash called twice ... re-get the fast hash, and then get the full hash
        if f.stat().mtime != mtime:
            assert len(m.mock_calls) == 2
        else:
            print("utime not supported in some vms")

    f.write(b"hi"*2000 + b"ho")
    h3 = fsp._fast_hash_path(str(f))
    assert h3 != h2

    f.write(b"hi")
    with patch("cloudsync.providers.filesystem.get_hash", side_effect=get_hash) as m:
        h1 = fsp._fast_hash_path(str(f))
        m.assert_called_once()

    assert h1 != h3


def test_cursor_prune(fsp):
    fsp._event_window = 20
    cs1 = fsp.latest_cursor

    for i in range(100):
        ev = watchdog_events.FileCreatedEvent("/file%s" % i)
        fsp._on_any_event(ev)

    i = 0
    last = None
    for ev in fsp.events():
        cpos = ev.new_cursor
        i += 1
        last = ev
    assert last.oid == "/file99"
    assert fsp.current_cursor == cpos

    assert i == 100

    fsp.current_cursor = cs1

    i = 0
    for ev in fsp.events():
        cpos = ev.new_cursor
        last = ev
        i += 1

    assert last.oid == "/file99"
    assert fsp.current_cursor == cpos

    assert i == 20
