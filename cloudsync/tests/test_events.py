import time
from io import BytesIO

import pytest

from cloudsync import EventManager, SyncState, LOCAL, CloudTokenError
from unittest.mock import patch, MagicMock
import logging
log = logging.getLogger(__name__)


@pytest.fixture(name="manager")
def fixture_manager(mock_provider_generator):
    # TODO extend this to take any provider
    provider = mock_provider_generator()
    state = SyncState((provider, provider), shuffle=True)

    ret = EventManager(provider, state, LOCAL, reauth=MagicMock())
    yield ret
    ret.stop()


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
    manager.start(sleep=.3)
    try:
        time.sleep(0.1)  # give it a chance to finish the first do() and get into the sleep before we create event
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
    manager.start(sleep=.3)
    try:
        time.sleep(0.1)  # give it a chance to finish the first do() and get into the sleep before we create event
        provider = manager.provider
        provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        assert provider.latest_cursor > provider.current_cursor
        manager.do()
        try:
            manager.events.__next__()
            assert False
        except StopIteration:
            pass
    finally:
        manager.stop()


def test_backoff(manager):
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
