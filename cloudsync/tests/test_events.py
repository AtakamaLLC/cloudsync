# pylint: disable=protected-access,too-many-lines,missing-docstring,logging-format-interpolation,too-many-statements,too-many-locals
import time
from io import BytesIO

import pytest

from cloudsync import (
    exceptions,
    EventManager,
    Event,
    SyncState,
    LOCAL,
    CloudTokenError,
    DIRECTORY,
    CloudRootMissingError,
    CloudCursorError, FILE,
)
from unittest.mock import patch, MagicMock
import logging
log = logging.getLogger(__name__)


class EventManagerWithCounter(EventManager):
    def __init__(self, *args, **kwargs):
        self.event_count = 0
        self.stop_after = -1
        super().__init__(*args, **kwargs)

    def _process_event(self, *args, **kwargs):
        super()._process_event(*args, **kwargs)
        self.event_count += 1
        if self.event_count == self.stop_after:
            self.stop()


def create_event_manager(provider_generator, root_path, event_manager_type=EventManager):
    provider = provider_generator()
    state = SyncState((provider, provider), shuffle=True)
    if provider.oid_is_path:
        root_oid = provider.mkdirs(root_path) if root_path else None
        provider.set_root(root_oid=root_oid)
        event_manager = event_manager_type(provider, state, LOCAL, reauth=MagicMock(), root_oid=root_oid)
    else:
        provider.set_root(root_path=root_path)
        event_manager = event_manager_type(provider, state, LOCAL, reauth=MagicMock(), root_path=root_path)
    event_manager._drain()
    return event_manager


@pytest.fixture(name="manager")
def fixture_manager(mock_provider_generator):
    # TODO extend this to take any provider
    ret = create_event_manager(mock_provider_generator, "/root")
    yield ret
    ret.stop()


@pytest.fixture(name="rootless_manager")
def fixture_rootless_manager(mock_provider_generator):
    # TODO extend this to take any provider
    ret = create_event_manager(mock_provider_generator, None)
    yield ret
    ret.stop()

@pytest.fixture(name="event_counter")
def fixture_event_counter(mock_provider_generator):
    ret = create_event_manager(mock_provider_generator, "/root", EventManagerWithCounter)
    yield ret
    ret.stop()


def make_event():
    return Event(FILE, "oid", "path", "hash", exists=True)


def test_event_basic(manager):
    provider = manager.provider
    state = manager.state
    create_path = provider.join(provider._root_path, "dest")
    info = provider.create(create_path, BytesIO(b'hello'))

    assert not state.lookup_path(LOCAL, create_path)

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

    assert info.path == create_path


def test_events_shutdown_event_shouldnt_process(manager):
    manager.start(sleep=.3)
    try:
        time.sleep(0.1)  # give it a chance to finish the first do() and get into the sleep before we create event
        provider = manager.provider
        provider.create("/dest", BytesIO(b'hello'))
        manager.stop()
        time.sleep(.4)
        try:
            manager.provider.events().__next__()
        except exceptions.CloudDisconnectedError:
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
            manager.provider.events().__next__()
            assert False
        except StopIteration:
            pass
    finally:
        manager.stop()


def test_events_stop_walk_processing(event_counter):
    with patch.object(event_counter.provider, "walk_oid", lambda x: [make_event()] * 10):
        with patch.object(event_counter.provider, "events", lambda: [make_event()] * 10):
            event_counter.stop_after = 5
            event_counter._do_unsafe()
            # walk event processing is interruptable
            assert event_counter.event_count == 5


def test_events_stop_queue_processing(event_counter):
    with patch.object(event_counter.provider, "walk_oid", lambda x: [make_event()] * 10):
        with patch.object(event_counter.provider, "events", lambda: [make_event()] * 10):
            event_counter._queue = [(None, True)] * 10
            event_counter.stop_after = 15
            event_counter._do_unsafe()
            # queue event processing is not interruptable - stop before the first provider event
            assert event_counter.event_count == 20


def test_events_stop_provider_processing(event_counter):
    event_counter.need_walk = False
    with patch.object(event_counter.provider, "events", lambda: [make_event()] * 10):
        event_counter.stop_after = 5
        event_counter._do_unsafe()
        # provider event processing is interruptible
        assert event_counter.event_count == 5


def test_events_no_stop(event_counter):
    with patch.object(event_counter.provider, "events", lambda: [make_event()] * 6):
        with patch.object(event_counter.provider, "walk_oid", lambda x: [make_event()] * 7):
            # _process_event() is is resilient to invalid events
            event_counter._queue = [(None, True)] * 8
            event_counter._do_unsafe()
            assert event_counter.event_count == 6 + 7 + 8


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

@pytest.mark.parametrize("mode", ["root", "no-root"])
def test_event_provider_contract(manager, rootless_manager, mode):
    if mode == "no-root":
        manager.done()
        manager = rootless_manager

    prov = manager.provider

    with pytest.raises(ValueError):
        # do not reuse provider while another EventManager is actively using it
        manager = EventManager(prov, MagicMock(), LOCAL)

    # ok to reuse provider once the other EventManager is done with it
    manager.done()
    manager = EventManager(prov, MagicMock(), LOCAL, root_path=prov._root_path, root_oid=prov._root_oid)

    manager.done()
    if mode == "root":
        assert prov.info_path(manager._root_path)
        assert prov.info_oid(manager._root_oid)
        assert prov.root_path == manager._root_path
        assert prov.root_oid == manager._root_oid
    else:
        foo = prov.create("/foo", BytesIO(b"oo"))
        prov.mkdir("/bar")
        bar = prov.info_path("/bar")
        with pytest.raises(CloudRootMissingError):
            prov.set_root(root_oid="does-not-exist")
        with pytest.raises(CloudRootMissingError):
            # not a directory oid
            prov.set_root(root_oid=foo.oid)
        with pytest.raises(CloudRootMissingError):
            # oid/path mismatch
            prov.set_root(root_path="/not-bar", root_oid=bar.oid)
        with pytest.raises(CloudRootMissingError):
            # not a directory path
            prov.set_root(root_path="/foo")
        # provider creates folder if it does not already exist
        prov.set_root(root_path="/new-folder")
        assert prov.info_path("/new-folder")
        manager._drain()

    manager.done()
    manager = EventManager(prov, MagicMock(), LOCAL, root_path=prov._root_path, root_oid=prov._root_oid)
    assert not manager.busy
    prov.mkdir("/busy-test")
    assert manager.busy
    manager.done()

    def raise_root_missing_error():
        raise CloudRootMissingError("unrooted")

    notify = MagicMock()
    manager = EventManager(prov, MagicMock(), LOCAL, notify, root_path=prov._root_path, root_oid=prov._root_oid)
    with patch.object(manager, "_reconnect_if_needed", raise_root_missing_error):
        with pytest.raises(Exception):
            # _BackoffError
            manager.do()
            notify.notify_from_exception.assert_called_once()
            assert not manager._root_validated

    with patch.object(manager, "_validate_root", raise_root_missing_error):
        with pytest.raises(Exception):
            # _BackoffError
            manager.do()
            notify.notify_from_exception.assert_called_once()
            assert not manager._root_validated

    prov.connection_id = None
    with pytest.raises(ValueError):
        # connection id is required
        manager = EventManager(prov, MagicMock(), LOCAL, root_path=prov._root_path, root_oid=prov._root_oid)


def test_event_root_change(manager):
    # root renamed
    with pytest.raises(CloudRootMissingError):
        event = Event(DIRECTORY, manager._root_oid, "/renamed", "hash-1", True)
        manager._notify_on_root_change_event(event)
    if manager.provider.oid_is_path:
        with pytest.raises(CloudRootMissingError):
            event = Event(DIRECTORY, "/renamed", "", "hash-1", True, prior_oid=f"{manager._root_path}")
            manager._notify_on_root_change_event(event)
    # root deleted
    with pytest.raises(CloudRootMissingError):
        event = Event(DIRECTORY, manager._root_oid, "", "hash-1", False)
        event.accurate = True
        manager._notify_on_root_change_event(event)

    # root still present ... but inaccurate event arrives
    event = Event(DIRECTORY, manager._root_oid, "", "hash-1", False)
    event.accurate = False
    # no error
    manager._notify_on_root_change_event(event)


def test_event_cursor_error(manager):
    manager.need_walk = False

    with patch.object(manager.provider, "events", side_effect=CloudCursorError):
        with pytest.raises(Exception):
            # _BackoffError
            manager.do()
        assert manager.need_walk


def test_event_no_info_oid_calls(manager):
    manager.need_walk = False
    oid1 = manager.provider.create("/file1", BytesIO(b'hello')).oid
    oid2 = manager.provider.create("/file2", BytesIO(b'hello')).oid

    def done():
        return manager.state.lookup_oid(manager.side, oid1) and manager.state.lookup_oid(manager.side, oid2)

    with patch.object(manager.provider, "info_oid", side_effect=manager.provider.info_oid) as api:

        # run until both oids are in the change set
        manager.run(timeout=1, until=done)

        # path is missing for oid providers
        if not manager.provider.oid_is_path:
            assert not manager.state.lookup_oid(manager.side, oid1)[manager.side].path
            assert not manager.state.lookup_oid(manager.side, oid2)[manager.side].path

        # info_oid() not called
        api.assert_not_called()
