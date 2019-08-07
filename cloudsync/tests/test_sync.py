import logging
from io import BytesIO
import pytest
from typing import NamedTuple

from cloudsync import SyncManager, SyncState, CloudFileNotFoundError, LOCAL, REMOTE, FILE, DIRECTORY
from cloudsync.provider import Provider


class WaitFor(NamedTuple):
    side: int = None
    path: str = None
    hash: bytes = None
    oid: str = None
    exists: bool = True


log = logging.getLogger(__name__)

TIMEOUT = 2


class RunUntilHelper:
    def run_until_found(self: SyncManager, *files, timeout=TIMEOUT):
        log.debug("running until found")
        last_error = None

        def found():
            ok = True

            for info in files:
                if type(info) is tuple:
                    info = WaitFor(side=info[0], path=info[1])

                try:
                    other_info = self.providers[info.side].info_path(info.path)
                except CloudFileNotFoundError:
                    other_info = None

                if other_info is None:
                    nonlocal last_error
                    if info.exists is False:
                        log.debug("waiting not exists %s", info.path)
                        continue
                    log.debug("waiting exists %s", info.path)
                    last_error = CloudFileNotFoundError(info.path)
                    ok = False
                    break

                if info.exists is False:
                    ok = False
                    break

                if info.hash and info.hash != other_info.hash:
                    log.debug("waiting hash %s", info.path)
                    ok = False
                    break

            return ok

        self.run(timeout=timeout, until=found)

        if not found():
            if last_error:
                raise TimeoutError("timed out while waiting: %s" % last_error)
            else:
                raise TimeoutError("timed out while waiting")


class SyncMgrMixin(SyncManager, RunUntilHelper):
    pass


@pytest.fixture(name="sync")
def fixture_sync(mock_provider_generator):
    state = SyncState()

    def translate(to, path):
        if to == LOCAL:
            return "/local" + path.replace("/remote", "")

        if to == REMOTE:
            return "/remote" + path.replace("/local", "")

        raise ValueError("bad path: %s", path)

    # two providers and a translation function that converts paths in one to paths in the other
    sync = SyncMgrMixin(state, (mock_provider_generator(), mock_provider_generator(oid_is_path=False)), translate)

    yield sync

    sync.done()


def test_sync_state_basic():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")

    assert state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="123")
    state._assert_index_is_correct()


def test_sync_state_rename():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state._assert_index_is_correct()


def test_sync_state_rename2():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo", oid="123", hash=b"foo")
    state.update(LOCAL, FILE, path="foo2", oid="456", prior_oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    assert state.lookup_oid(LOCAL, oid="456")
    assert not state.lookup_oid(LOCAL, oid="123")
    state._assert_index_is_correct()


def test_sync_state_rename3():
    state = SyncState()
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

    state._assert_index_is_correct()


def test_sync_state_multi():
    state = SyncState()
    state.update(LOCAL, FILE, path="foo2", oid="123")
    assert state.lookup_path(LOCAL, path="foo2")
    assert not state.lookup_path(LOCAL, path="foo")
    state._assert_index_is_correct()


def test_sync_basic(sync: "SyncMgrMixin"):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = Provider.join(remote_parent, "stuff1")
    local_path1 = sync.translate(LOCAL, remote_path1)
    local_path1.replace("\\", "/")
    assert local_path1 == "/local/stuff1"
    Provider.join(local_parent, "stuff2")  # "/local/stuff2"
    remote_path2 = Provider.join(remote_parent, "stuff2")  # "/remote/stuff2"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.state.update(LOCAL, FILE, oid=linfo.oid, exists=True)

    assert sync.state.entry_count() == 1

    rinfo = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

    # inserts info about some cloud path
    sync.state.update(REMOTE, FILE, oid=rinfo.oid,
                      path=remote_path2, hash=rinfo.hash)

    def done():
        has_info = [None] * 4
        try:
            has_info[0] = sync.providers[LOCAL].info_path("/local/stuff1")
            has_info[1] = sync.providers[LOCAL].info_path("/local/stuff2")
            has_info[2] = sync.providers[REMOTE].info_path("/remote/stuff2")
            has_info[3] = sync.providers[REMOTE].info_path("/remote/stuff2")
        except CloudFileNotFoundError as e:
            log.debug("waiting for %s", e)
            pass

        return all(has_info)

    # loop the sync until the file is found
    sync.run(timeout=TIMEOUT, until=done)

    assert done()

    info = sync.providers[LOCAL].info_path("/local/stuff2")
    assert info.hash == sync.providers[LOCAL].hash_oid(info.oid)
    assert info.oid
    log.debug("all state %s", sync.state.get_all())

    sync.state._assert_index_is_correct()


def test_sync_rename(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = Provider.join(local_parent, "stuff1")  # "/local/stuff1"
    local_path2 = Provider.join(local_parent, "stuff2")  # "/local/stuff2"
    remote_path1 = Provider.join(remote_parent, "stuff1")  # "/remote/stuff1"
    remote_path2 = Provider.join(remote_parent, "stuff2")  # "/remote/stuff2"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    new_oid = sync.providers[LOCAL].rename(linfo.oid, local_path2)

    sync.state.update(LOCAL, FILE, path=local_path2,
                      oid=new_oid, hash=linfo.hash, prior_oid=linfo.oid)

    sync.run_until_found((REMOTE, remote_path2))

    assert sync.providers[REMOTE].info_path("/remote/stuff") is None
    sync.state._assert_index_is_correct()


def test_sync_hash(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = "/local/stuff1"
    remote_path1 = "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    linfo = sync.providers[LOCAL].upload(linfo.oid, BytesIO(b"hello2"))

    sync.state.update(LOCAL, FILE, linfo.oid, hash=linfo.hash)

    sync.run_until_found(WaitFor(REMOTE, remote_path1, hash=linfo.hash))

    info = sync.providers[REMOTE].info_path(remote_path1)

    check = BytesIO()
    sync.providers[REMOTE].download(info.oid, check)

    assert check.getvalue() == b"hello2"
    sync.state._assert_index_is_correct()


def test_sync_rm(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = Provider.join(local_parent, "stuff1")  # "/local/stuff1"
    remote_path1 = Provider.join(remote_parent, "stuff1")  # "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    sync.providers[LOCAL].delete(linfo.oid)
    sync.state.update(LOCAL, FILE, linfo.oid, exists=False)

    sync.run_until_found(WaitFor(REMOTE, remote_path1, exists=False))

    assert sync.providers[REMOTE].info_path(remote_path1) is None

    sync.state._assert_index_is_correct()


def test_sync_mkdir(sync):
    local_dir1 = "/local"
    local_path1 = "/local/stuff"
    remote_dir1 = "/remote"
    remote_path1 = "/remote/stuff"

    local_dir_oid1 = sync.providers[LOCAL].mkdir(local_dir1)
    local_path_oid1 = sync.providers[LOCAL].mkdir(local_path1)

    # inserts info about some local path
    sync.state.update(LOCAL, DIRECTORY, path=local_dir1,
                      oid=local_dir_oid1)
    sync.state.update(LOCAL, DIRECTORY, path=local_path1,
                      oid=local_path_oid1)

    sync.run_until_found((REMOTE, remote_dir1))
    sync.run_until_found((REMOTE, remote_path1))

    log.debug("BEFORE DELETE\n %s", sync.state.pretty_print())

    sync.providers[LOCAL].delete(local_path_oid1)
    sync.state.update(LOCAL, FILE, local_path_oid1, exists=False)

    log.debug("AFTER DELETE\n %s", sync.state.pretty_print())

    log.debug("wait for delete")
    sync.run_until_found(WaitFor(REMOTE, remote_path1, exists=False))

    assert sync.providers[REMOTE].info_path(remote_path1) is None
    sync.state._assert_index_is_correct()


def test_sync_conflict_simul(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = Provider.join(local_parent, "stuff1")  # "/local/stuff1"
    remote_path1 = Provider.join(remote_parent, "stuff1")  # "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)

    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))
    rinfo = sync.providers[REMOTE].create(remote_path1, BytesIO(b"goodbye"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)
    sync.state.update(REMOTE, FILE, path=remote_path1,
                      oid=rinfo.oid, hash=rinfo.hash)

    sync.run_until_found(
        (REMOTE, "/remote/stuff1.conflicted"),
        (LOCAL, "/local/stuff1.conflicted"),
        (REMOTE, "/remote/stuff1"),
        (LOCAL, "/local/stuff1")
    )

    sync.providers[LOCAL].log_debug_state("LOCAL")
    sync.providers[REMOTE].log_debug_state("REMOTE")

    b1 = BytesIO()
    b2 = BytesIO()
    sync.providers[REMOTE].download_path("/remote/stuff1.conflicted", b1)
    sync.providers[REMOTE].download_path("/remote/stuff1", b2)

    # both files are intact
    assert b1.getvalue() != b2.getvalue()
    assert b1.getvalue() in (b"hello", b"goodbye")
    assert b2.getvalue() in (b"hello", b"goodbye")
    sync.state._assert_index_is_correct()


def test_sync_conflict_path(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = "/local/stuff"
    remote_path1 = "/remote/stuff"
    local_path2 = "/local/stuff-l"
    remote_path2 = "/remote/stuff-r"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)

    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    rinfo = sync.providers[REMOTE].info_path(remote_path1)

    assert len(sync.state.get_all()) == 1

    ent = sync.state.get_all().pop()

    sync.providers[REMOTE].log_debug_state("BEFORE")

    new_oid_l = sync.providers[LOCAL].rename(linfo.oid, local_path2)
    new_oid_r = sync.providers[REMOTE].rename(rinfo.oid, remote_path2)

    sync.providers[REMOTE].log_debug_state("AFTER")

    sync.state.update(LOCAL, FILE, path=local_path2,
                      oid=new_oid_l, hash=linfo.hash, prior_oid=linfo.oid)

    assert len(sync.state.get_all()) == 1
    assert ent[REMOTE].oid == new_oid_r

    sync.state.update(REMOTE, FILE, path=remote_path2,
                      oid=new_oid_r, hash=rinfo.hash, prior_oid=rinfo.oid)

    assert len(sync.state.get_all()) == 1

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    # currently defers to the alphabetcially greater name, rather than conflicting
    sync.run_until_found((LOCAL, "/local/stuff-r"))
    
    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    assert not sync.providers[LOCAL].exists_path(local_path1)
    assert not sync.providers[LOCAL].exists_path(local_path2)
    sync.state._assert_index_is_correct()


def test_sync_conflict_path_combine(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = "/local/stuff1"
    local_path2 = "/local/stuff2"
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff2"
    local_path3 = "/local/stuff"
    remote_path3 = "/remote/stuff"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)

    linfo1 = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))
    rinfo2 = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello"))

    # inserts info about some local path
    sync.state.update(LOCAL, FILE, path=local_path1,
                      oid=linfo1.oid, hash=linfo1.hash)

    sync.state.update(REMOTE, FILE, path=remote_path2,
                      oid=rinfo2.oid, hash=rinfo2.hash)

    sync.run_until_found((REMOTE, remote_path1), (LOCAL, local_path2))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    new_oid1 = sync.providers[LOCAL].rename(linfo1.oid, local_path3)
    prior_oid = sync.providers[LOCAL].oid_is_path and linfo1.oid
    sync.state.update(LOCAL, FILE, path=local_path3, oid=new_oid1, prior_oid=prior_oid)

    new_oid2 = sync.providers[REMOTE].rename(rinfo2.oid, remote_path3)
    prior_oid = sync.providers[REMOTE].oid_is_path and rinfo2.oid
    sync.state.update(REMOTE, FILE, path=remote_path3, oid=new_oid2, prior_oid=prior_oid)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    sync.run_until_found((LOCAL, "/local/stuff.conflicted"))

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())
