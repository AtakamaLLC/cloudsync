# pylint: disable=protected-access,too-many-lines,missing-docstring,logging-format-interpolation,too-many-statements,too-many-locals

import time
from io import BytesIO

import pytest

from cloudsync import exceptions, EventManager, Event, SyncState, LOCAL, CloudTokenError, FILE, DIRECTORY, CloudRootMissingError
from unittest.mock import patch, MagicMock
import logging
log = logging.getLogger(__name__)


def create_event_manager(provider_generator, root_path):
    provider = provider_generator()
    if root_path:
        provider.mkdir(root_path)
    state = SyncState((provider, provider), shuffle=True)
    if provider.oid_is_path:
        event_manager = EventManager(provider, state, LOCAL, reauth=MagicMock(), root_oid=root_path)
    else:
        event_manager = EventManager(provider, state, LOCAL, reauth=MagicMock(), root_path=root_path)
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
        with pytest.raises(ValueError):
            manager = EventManager(prov, MagicMock(), LOCAL, root_path="/cannot-change-after-set")
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

    prov.connection_id = None
    with pytest.raises(ValueError):
        # connection id is required
        manager = EventManager(prov, MagicMock(), LOCAL, root_path=prov._root_path, root_oid=prov._root_oid)


def test_event_filter(manager):
    # no filtering for oid-is-path providers for now
    if manager.provider.oid_is_path:
        event = Event(FILE, "", "", "", False)
        assert not manager._filter_event(event)
        return

    # filter out delete of unknown oid
    event = Event(FILE, "", "", "", False)
    assert manager._filter_event(event)
    # filter out create of unknown oid for a path we don't care about
    event = Event(FILE, "oid-1", "/some-random-path/file-1", "hash-1", True)
    assert manager._filter_event(event)
    # rename out of root path - do not filter out
    path = f"{manager._root_path}/file-1"
    oid = path if manager.provider.oid_is_path else "oid-1"
    event = Event(FILE, oid, path, "hash-1", True)
    manager._process_event(event)
    rename_path = "/some-other-path/file-1"
    rename_oid = rename_path if manager.provider.oid_is_path else oid
    event = Event(FILE, rename_oid, rename_path, "hash-1", True)
    event.prior_oid = oid if manager.provider.oid_is_path else None
    assert not manager._filter_event(event)
    # delete a file
    path = f"{manager._root_path}/file-2"
    oid = path if manager.provider.oid_is_path else "oid-2"
    event = Event(FILE, oid, path, "hash-1", True)
    manager._process_event(event)
    event = Event(FILE, oid, None, None, False)
    assert not manager._filter_event(event)
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
        manager._notify_on_root_change_event(event)


def test_event_filter_rootless(rootless_manager):
    # rootless event managers don't filter anything out
    event = Event(FILE, "", "", "", True)
    assert not rootless_manager._filter_event(event)
    event = Event(DIRECTORY, "", "", "", False)
    assert not rootless_manager._filter_event(event)
    assert not rootless_manager._filter_event(None)
    assert not rootless_manager._filter_event("foo-bar")
