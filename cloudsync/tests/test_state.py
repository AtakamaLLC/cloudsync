import logging
from io import BytesIO
from typing import Dict, Any

import pytest

from cloudsync import SyncState, SyncEntry, LOCAL, REMOTE, FILE, DIRECTORY
from .fixtures import MockStorage

log = logging.getLogger(__name__)

def test_state_basic(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")

    assert state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="123")
    state.assert_index_is_correct()


def test_state_rename(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state.assert_index_is_correct()


def test_state_rename2(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    assert state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, "123")
    state.update(LOCAL, FILE, path="foo2", oid="456", prior_oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert state.lookup_oid(LOCAL, "456")
    assert not state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="456")
    assert not state.lookup_oid(LOCAL, oid="123")
    state.assert_index_is_correct()


def test_state_rename3(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    ahash = "ah"
    bhash = "bh"
    state.update(LOCAL, FILE, path="a", oid="a", hash=ahash)
    state.update(LOCAL, FILE, path="b", oid="b", hash=bhash)

    infoa = state.lookup_oid(LOCAL, "a")
    infob = state.lookup_oid(LOCAL, "b")

    assert infoa[LOCAL].hash == ahash
    assert infob[LOCAL].hash == bhash

    # rename in a circle

    state.update(LOCAL, FILE, path="c", oid="c", prior_oid="a")
    log.debug("TABLE 0:\n%s", state.pretty_print(use_sigs=False))
    state.update(LOCAL, FILE, path="a", oid="a", prior_oid="b")
    log.debug("TABLE 1:\n%s", state.pretty_print(use_sigs=False))
    state.update(LOCAL, FILE, path="b", oid="b", prior_oid="c")
    log.debug("TABLE 2:\n%s", state.pretty_print(use_sigs=False))

    assert state.lookup_path(LOCAL, "a")
    assert state.lookup_path(LOCAL, "b")
    infoa = state.lookup_oid(LOCAL, "a")
    infob = state.lookup_oid(LOCAL, "b")

    # hashes should be flipped
    assert infoa[LOCAL].hash == bhash
    assert infob[LOCAL].hash == ahash

    state.assert_index_is_correct()


def test_state_multi(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state.assert_index_is_correct()


def test_state_kids(mock_provider):
    # annoyingly, the state manager now interacts with the provider
    # this means that the state manager needs to know how to get an oid

    # TODO: make a layer that knows about providers and state, and ANOTHER layer that just knows about state
    # that way we can go back to have a pure state/storage manager

    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, DIRECTORY, path="/dir", oid="123")
    assert state.lookup_path(LOCAL, path="/dir")
    state.update(LOCAL, FILE, path="/dir/foo", oid="124")
    assert state.lookup_path(LOCAL, path="/dir/foo")
    new_oid = mock_provider.mkdir("/dir2")
    mock_provider.create("/dir2/foo", BytesIO(b'hi'))
    state.update(LOCAL, DIRECTORY, path="/dir2", oid=new_oid, prior_oid="123")

    log.debug("TABLE:\n%s", state.pretty_print(use_sigs=False))

    state.assert_index_is_correct()
    assert len(state) == 2
    assert state.lookup_path(LOCAL, "/dir2/foo")

def test_state_split(mock_provider):
    # annoyingly, the state manager now interacts with the provider
    # this means that the state manager needs to know how to get an oid

    # TODO: make a layer that knows about providers and state, and ANOTHER layer that just knows about state
    # that way we can go back to have a pure state/storage manager

    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)

    state.update(LOCAL, DIRECTORY, path="/dir", oid="123")

    ent = state.lookup_oid(LOCAL, "123")

    # oid/path updated
    ent[REMOTE].oid = "999"
    ent[REMOTE].path = "/rem"

    assert state.lookup_oid(LOCAL, "123")
    assert state.lookup_path(LOCAL, "/dir")

    assert state.lookup_path(REMOTE, "/rem")
    assert state.lookup_oid(REMOTE, "999")

    (defer, _ds, repl, _rs) = state.split(ent)

    assert state.lookup_oid(LOCAL, "123") is repl
    assert state.lookup_path(LOCAL, "/dir")

    assert state.lookup_path(REMOTE, "/rem")
    assert state.lookup_oid(REMOTE, "999") is defer

    state.assert_index_is_correct()

def test_state_alter_oid(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="123", oid="123", hash="123")
    ent1 = state.lookup_oid(LOCAL, "123")
    assert ent1 in state.changes
    state.update(LOCAL, FILE, path="456", oid="456", hash="456")
    ent2 = state.lookup_oid(LOCAL, "456")
    assert ent2[LOCAL].changed
    assert ent2 in state.changes
    ent1[LOCAL].oid = "456"
    assert state.lookup_oid(LOCAL, "456") is ent1
    assert state.lookup_oid(LOCAL, "123") is None
    assert ent2 not in state.get_all()
    ent1[LOCAL].oid = "456"
    ent2[LOCAL].oid = "123"
    assert ent2[LOCAL].changed
    assert state.lookup_oid(LOCAL, "123") is ent2
    assert ent2 in state.changes


def entries_equal(e1, e2):
    if e1.serialize() != e2.serialize():
        log.debug("serialize diff %s != %s", e1.serialize(), e2.serialize())
        return False
    for side in (LOCAL, REMOTE):
        for fd in ("hash", "sync_hash"):
            if getattr(e1[side], fd) != getattr(e2[side], fd):
                log.debug("side %s, %s diff %s!=%s", side, fd, getattr(e1[side], fd), getattr(e2[side], fd))
                return False
    return True


def state_diff(st1, st2):
    log.debug("TABLE 1:\n%s", st1.pretty_print(use_sigs=False))
    log.debug("TABLE 2:\n%s", st2.pretty_print(use_sigs=False))
    sd = []
    for name, func in [("all", lambda a: a.get_all()), ("changes", lambda a: a.changes)]:
        found2 = set()
        for e1 in func(st1):
            found = False
            for e2 in func(st2):
                if entries_equal(e1, e2):
                    found = True
                    found2.add(e2)
                    break
            if not found:
                if not e1.is_trash:
                    sd.append([name, str(e1)])
        for e2 in func(st2):
            if e2 not in found2:
                if not e2.is_trash:
                    sd.append([name, e2])
    return sd


def test_state_storage(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")
    state.update(LOCAL, FILE, path="123", oid="123", hash=b"123")
    state.storage_commit()

    state2 = SyncState(providers, storage, tag="whatever")
    assert not state_diff(state, state2)


def test_state_storage2(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")

    state.update(LOCAL, FILE, path="123", oid="123", hash="123")
    state.storage_commit()

    ent1 = state.lookup_oid(LOCAL, "123")
    ent1[LOCAL].oid = "456"
    state.storage_commit()

    state2 = SyncState(providers, storage, tag="whatever")
    assert not state_diff(state, state2)


def test_state_storage3(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")

    state.update(LOCAL, FILE, path="123", oid="123", hash=("123",))
    ent1 = state.lookup_oid(LOCAL, "123")
    ent1[REMOTE].oid = "456"
    ent1[REMOTE].path = "456"
    ent1[REMOTE].hash = "456"
    ent1[REMOTE].changed = -1
    (defer, _ds, repl, _rs) = state.split(ent1)
    state.storage_commit()

    state2 = SyncState(providers, storage, tag="whatever")
    assert not state_diff(state, state2)


def test_state_storage4(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")

    state.update(LOCAL, FILE, path="123", oid="123", hash=b"123")
    ent1 = state.lookup_oid(LOCAL, "123")

    entx = SyncEntry(state, FILE)
    entx[LOCAL].oid = "123"
    entx[LOCAL].path = "new"
    state.storage_commit()

    assert ent1[LOCAL].oid is None

    state2 = SyncState(providers, storage, tag="whatever")
    assert not state_diff(state, state2)


def test_state_storage_bad_hash(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")

    state.update(LOCAL, FILE, path="123", oid="123", hash=["123",])
    state.storage_commit()
    state2 = SyncState(providers, storage, tag="whatever")
    assert state_diff(state, state2), "tuples used instead of lists"


def test_state_storage_corrupt_input(mock_provider):
    providers = (mock_provider, mock_provider)
    backend: Dict[Any, Any] = {}
    storage = MockStorage(backend)
    state = SyncState(providers, storage, tag="whatever")
    state.update(LOCAL, FILE, path="123", oid="123", hash=b"123")
    state.update(LOCAL, FILE, path="456", oid="456", hash=b"456")
    state.storage_commit()

    tag = state._tag
    eid = state.lookup_oid(LOCAL, "123").storage_id
    state._storage.update(tag, b"crappy bad stuff", eid)

    state2 = SyncState(providers, storage, tag="whatever")

    # 123 record was corrupt, but 456 is still cool
    assert not state2.lookup_oid(LOCAL, "123")
    assert state2.lookup_oid(LOCAL, "456")
