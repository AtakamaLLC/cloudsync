import shutil

import pytest

from cloudsync.providers import FileSystemProvider
from watchdog import events as watchdog_events


@pytest.fixture
def fsp():
    fsp = FileSystemProvider()
    ns = fsp._test_namespace
    fsp.namespace = ns
    yield fsp
    shutil.rmtree(ns)

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
