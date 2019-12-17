import time
from io import BytesIO
import threading

import pytest

from cloudsync import EventManager, SyncState, LOCAL, CloudTokenError
from unittest.mock import patch, MagicMock

@pytest.fixture(name="manager")
def fixture_manager(mock_provider_generator):
    # TODO extend this to take any provider
    provider = mock_provider_generator()
    state = SyncState((provider, provider), shuffle=True)

    yield EventManager(provider, state, LOCAL, reauth=MagicMock())


def test_event_basic(manager):
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
        return False

    # loop the sync until the file is found
    manager.run(timeout=1, until=done)

    assert oid

    info = provider.info_oid(oid)

    assert info.path == "/dest"


def test_events_shutdown_event_shouldnt_process(manager):
    handle = threading.Thread(target=manager.run, kwargs={'sleep': .3}, daemon=True)
    handle.start()
    try:
        provider = manager.provider
        provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        try:
            manager.events.__next__()
        except StopIteration:
            assert False
        try:
            manager.events.__next__()
            assert False
        except StopIteration:
            pass
    finally:
        manager.stop()


def test_events_shutdown_force_process_event(manager):
    handle = threading.Thread(target=manager.run, kwargs={'sleep': .3}, daemon=True)
    handle.start()
    try:
        provider = manager.provider
        provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        manager.do()
        try:
            manager.events.__next__()
            assert False
        except StopIteration:
            pass
    finally:
        manager.stop()


def test_backoff(manager):
    handle = threading.Thread(target=manager.run, kwargs={'sleep': .3}, daemon=True)
    handle.start()
    try:
        provider = manager.provider
        provider.create("/dest", BytesIO(b'hello'))
        provider.disconnect()

        called = 0

        def fail_to_connect(creds):
            nonlocal called
            called = True
            raise CloudTokenError()

        with patch.object(provider, "connect", fail_to_connect):
            manager.start(until=lambda: called, timeout=1)
            manager.wait()

        assert manager.in_backoff
        prev_backoff = manager.in_backoff

        called = 0
        with patch.object(provider, "connect", fail_to_connect):
            manager.start(until=lambda: called, timeout=1)
            manager.wait()
        assert manager.in_backoff > prev_backoff

        assert manager.reauthenticate.call_count > 0

        manager.start(until=lambda: provider.connected, timeout=1)
        manager.wait()
    finally:
        manager.stop()
