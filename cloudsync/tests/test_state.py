import logging
from io import BytesIO

from cloudsync import SyncState, LOCAL, REMOTE, FILE, DIRECTORY

log = logging.getLogger(__name__)

def test_state_state_basic(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")

    assert state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="123")
    state.assert_index_is_correct()


def test_state_state_rename(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state.assert_index_is_correct()


def test_state_state_rename2(mock_provider):
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


def test_state_state_rename3(mock_provider):
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


def test_state_state_multi(mock_provider):
    providers = (mock_provider, mock_provider)
    state = SyncState(providers, shuffle=True)
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state.assert_index_is_correct()


def test_state_state_kids(mock_provider):
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

def test_state_state_split(mock_provider):
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
