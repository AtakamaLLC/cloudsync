import os
import time
from io import BytesIO
import pytest
import threading

from cloudsync import EventManager, SyncState, LOCAL


@pytest.fixture(name="manager")
def fixture_manager(mock_provider_generator):
    # TODO extend this to take any provider
    state = SyncState()
    provider = mock_provider_generator()

    yield EventManager(provider, state, LOCAL)


def test_event_basic(util, manager):
    provider = manager.provider
    state = manager.state
    info = provider.create("/dest", BytesIO(b'hello'))

    assert not state.lookup_path(LOCAL, "/dest")

    oid = None

    # this is normally a blocking function that runs forever
    def done():
        nonlocal oid
        states = state.get_all()
        if states:
            oid = list(states)[0][LOCAL].oid
            return state.lookup_oid(LOCAL, oid)

    # loop the sync until the file is found
    manager.run(timeout=1, until=done)

    assert oid

    info = provider.info_oid(oid)

    assert info.path == "/dest"

def test_events_shutdown_event_shouldnt_process(util, manager):
    handle = threading.Thread(target=manager.run, **{'kwargs': {'sleep': .3}})
    handle.start()
    try:
        provider = manager.provider
        info = provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        try:
            event = manager.events.__next__()
        except StopIteration:
            assert(False)
        try:
            event = manager.events.__next__()
            assert(False)
        except StopIteration:
            pass
    finally:
        manager.stop()

def test_events_shutdown_force_process_event(util, manager):
    handle = threading.Thread(target=manager.run, **{'kwargs': {'sleep': .3}})
    handle.start()
    try:
        provider = manager.provider
        info = provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        manager.do()
        try:
            event = manager.events.__next__()
            assert(False)
        except StopIteration:
            pass
    finally:
        manager.stop()
