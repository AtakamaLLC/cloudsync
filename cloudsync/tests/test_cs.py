from io import BytesIO
import logging
import pytest
from typing import List

from .fixtures import MockProvider, MockStorage
from cloudsync.sync.sqlite_storage import SqliteStorage
from cloudsync import Storage, CloudSync, SyncState, SyncEntry, LOCAL, REMOTE, FILE, DIRECTORY
from cloudsync.event import EventManager

from .test_sync import WaitFor, RunUntilHelper

log = logging.getLogger(__name__)


@pytest.fixture(name="cs")
def fixture_cs(mock_provider_generator):
    roots = ("/local", "/remote")

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    cs = CloudSyncMixin((mock_provider_generator(), mock_provider_generator()), roots, sleep=None)

    yield cs

    cs.done()


@pytest.fixture(name="multi_cs")
def fixture_multi_cs(mock_provider_generator):
    storage_dict = dict()
    storage = MockStorage(storage_dict)

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    p1 = mock_provider_generator()
    p2 = mock_provider_generator()
    p3 = mock_provider_generator()

    roots1 = ("/local1", "/remote")
    roots2 = ("/local2", "/remote")

    cs1 = CloudSyncMixin((p1, p2), roots1, storage, sleep=None)
    cs2 = CloudSyncMixin((p1, p3), roots2, storage, sleep=None)

    yield cs1, cs2

    cs1.done()
    cs2.done()


def test_sync_multi(multi_cs):
    cs1, cs2 = multi_cs

    local_parent1 = "/local1"
    local_parent2 = "/local2"
    remote_parent1 = "/remote"
    remote_parent2 = "/remote"
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff2"
    local_path11 = "/local1/stuff1"
    local_path21 = "/local2/stuff1"
    local_path12 = "/local1/stuff2"
    local_path22 = "/local2/stuff2"

    cs1.providers[LOCAL].mkdir(local_parent1)
    cs1.providers[REMOTE].mkdir(remote_parent1)
    cs2.providers[LOCAL].mkdir(local_parent2)
    cs2.providers[REMOTE].mkdir(remote_parent2)
    linfo1 = cs1.providers[LOCAL].create(local_path11, BytesIO(b"hello1"), None)
    linfo2 = cs2.providers[LOCAL].create(local_path21, BytesIO(b"hello2"), None)
    rinfo1 = cs1.providers[REMOTE].create(remote_path2, BytesIO(b"hello3"), None)
    rinfo2 = cs2.providers[REMOTE].create(remote_path2, BytesIO(b"hello4"), None)

    assert linfo1 and linfo2 and rinfo1 and rinfo2

    cs1.run_until_found(
        (LOCAL, local_path11),
        (LOCAL, local_path21),
        (REMOTE, remote_path1),
        (REMOTE, remote_path2),
        timeout=2)

    cs1.run(until=lambda: not cs1.state.has_changes(), timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 4      # 2 dirs, 2 files, 1 never synced (local2 file)

    try:
        cs2.run_until_found(
            (LOCAL, local_path12),
            (LOCAL, local_path22),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
            timeout=2)
    except TimeoutError:
        log.info("Timeout: TABLE 1\n%s", cs1.state.pretty_print())
        log.info("Timeout: TABLE 2\n%s", cs2.state.pretty_print())
        raise

    linfo12 = cs1.providers[LOCAL].info_path(local_path12)
    rinfo11 = cs1.providers[REMOTE].info_path(remote_path1)
    linfo22 = cs2.providers[LOCAL].info_path(local_path22)
    rinfo21 = cs2.providers[REMOTE].info_path(remote_path1)

    assert linfo12.oid
    assert linfo22.oid
    assert rinfo11.oid
    assert rinfo21.oid
    assert linfo12.hash == rinfo1.hash
    assert linfo22.hash == rinfo2.hash

    # let cleanups/discards/dedups happen if needed
    cs2.run(until=lambda: not cs2.state.has_changes(), timeout=1)
    log.info("TABLE\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 4
    assert len(cs2.state) == 4


def test_sync_basic(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"
    remote_path2 = "/remote/stuff2"
    local_path2 = "/local/stuff2"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    rinfo2 = cs.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"), None)

    cs.run_until_found(
        (LOCAL, local_path1),
        (LOCAL, local_path2),
        (REMOTE, remote_path1),
        (REMOTE, remote_path2),
        timeout=2)

    linfo2 = cs.providers[LOCAL].info_path(local_path2)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo2.oid
    assert rinfo1.oid
    assert linfo2.hash == rinfo2.hash
    assert linfo1.hash == rinfo1.hash

    assert not cs.providers[LOCAL].info_path(local_path2 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    # let cleanups/discards/dedups happen if needed
    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)
    log.info("TABLE\n%s", cs.state.pretty_print())

    assert len(cs.state) == 4
    assert not cs.state.has_changes()


def setup_remote_local(cs, *names):
    remote_parent = "/remote"
    local_parent = "/local"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    found = []
    for name in names:
        remote_path1 = "/remote/" + name
        local_path1 = "/local/" + name
        linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))
        found.append((REMOTE, remote_path1))

    cs.run_until_found(*found)
    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)


def test_sync_create_delete_same_name(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    cs.run(until=lambda: not cs.state.has_changes(), timeout=2)

    rinfo = cs.providers[REMOTE].info_path(remote_path1)

    cs.emgrs[LOCAL].do()

    cs.providers[LOCAL].delete(linfo1.oid)

    cs.emgrs[LOCAL].do()

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))

    # run local event manager only... not sync
    cs.emgrs[LOCAL].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print())
    # local and remote dirs can be disjoint

#    assert(len(cs.state) == 3 or len(cs.state) == 2)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    # local and remote dirs can be disjoint
#    assert(len(cs.state) == 3 or len(cs.state) == 2)

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    rinfo = cs.providers[REMOTE].info_path(remote_path1)
    bio = BytesIO()
    cs.providers[REMOTE].download(rinfo.oid, bio)
    assert bio.getvalue() == b'goodbye'


def test_sync_two_conflicts(cs):
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.providers[REMOTE].delete(rinfo1.oid)

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))
    linfo2 = cs.providers[REMOTE].create(remote_path1, BytesIO(b"world"))

    # run event managers only... not sync
    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print())
    if cs.providers[LOCAL].oid_is_path:
        # the local delete/create doesn't add entries
        assert(len(cs.state) == 3)
    else:
        assert(len(cs.state) == 5)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())
    assert(len(cs.state) == 4)

    assert cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    b1 = BytesIO()
    b2 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, b1)
    cs.providers[LOCAL].download_path(local_path1 + ".conflicted", b2)

    assert b1.getvalue() in (b'goodbye', b'world')
    assert b2.getvalue() in (b'goodbye', b'world')
    assert b1.getvalue() != b2.getvalue()


@pytest.mark.repeat(10)
def test_sync_subdir_rename(cs):
    local_dir = "/local/a"
    local_base = "/local/a/stuff"
    local_dir2 = "/local/b"
    local_base2 = "/local/b/stuff"
    remote_dir = "/remote/a"
    remote_dir2 = "/remote/b"
    remote_base = "/remote/a/stuff"
    remote_base2 = "/remote/b/stuff"

    kid_count = 4
    cs.providers[LOCAL].mkdir("/local")

    lpoid = cs.providers[LOCAL].mkdir(local_dir)

    lpaths = []
    rpaths = []
    rpaths2 = []
    for i in range(kid_count):
        lpath = local_base + str(i)
        rpath = remote_base + str(i)
        rpath2 = remote_base2 + str(i)

        cs.providers[LOCAL].create(lpath, BytesIO(b'hello'))

        lpaths.append(lpath)
        rpaths.append((REMOTE, rpath))
        rpaths2.append((REMOTE, rpath2))

    cs.run_until_found(*rpaths, timeout=2)

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    cs.providers[LOCAL].rename(lpoid, local_dir2)

    for _ in range(10):
        cs.do()

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.run_until_found(*rpaths2, timeout=2)

    log.info("TABLE 2\n%s", cs.state.pretty_print())

# this test is sensitive to the order in which things are processed
# so run it a few times


@pytest.mark.repeat(10)
def test_sync_folder_conflicts_file(cs):
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff1/under"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.providers[REMOTE].delete(rinfo1.oid)

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))
    linfo2 = cs.providers[REMOTE].mkdir(remote_path1)
    linfo2 = cs.providers[REMOTE].create(remote_path2, BytesIO(b"world"))

    # run event managers only... not sync
    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print())
    if cs.providers[LOCAL].oid_is_path:
        # there won't be 2 rows for /local/stuff1 is oid_is_path
        assert(len(cs.state) == 4)
        locs = cs.state.lookup_path(LOCAL, local_path1)
        assert locs and len(locs) == 1
        loc = locs[0]
        assert loc[LOCAL].otype == FILE
        assert loc[REMOTE].otype == DIRECTORY
    else:
        # deleted /local/stuff, remote/stuff, remote/stuff/under, lcoal/stuff, /local
        assert(len(cs.state) == 6)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())
    assert(len(cs.state) == 6 or len(cs.state) == 5)

    local_conf = cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    remote_conf = cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    assert local_conf and remote_conf


@pytest.fixture(params=[(MockStorage, dict()), (SqliteStorage, 'file::memory:?cache=shared')],
                ids=["mock_storage", "sqlite_storage"],
                name="storage"
                )
def storage_fixture(request):
    return request.param


def test_storage(storage):
    roots = ("/local", "/remote")
    storage_class = storage[0]
    storage_mechanism = storage[1]

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    p1 = MockProvider(oid_is_path=False, case_sensitive=True)
    p2 = MockProvider(oid_is_path=False, case_sensitive=True)

    storage1: Storage = storage_class(storage_mechanism)
    cs1: CloudSync = CloudSyncMixin((p1, p2), roots, storage1, sleep=None)
    old_cursor = cs1.emgrs[0].state.storage_get_cursor(cs1.emgrs[0]._cursor_tag)
    assert old_cursor is not None
    log.debug("cursor=%s", old_cursor)

    test_sync_basic(cs1)  # do some syncing, to get some entries into the state table

    storage2 = storage_class(storage_mechanism)
    cs2: CloudSync = CloudSyncMixin((p1, p2), roots, storage2, sleep=None)

    print(f"state1 = {cs1.state.entry_count()}\n{cs1.state.pretty_print()}")
    print(f"state2 = {cs2.state.entry_count()}\n{cs2.state.pretty_print()}")

    def not_dirty(s: SyncState):
        for se in s.get_all():
            se: SyncEntry
            assert not se.dirty

    def compare_states(s1: SyncState, s2: SyncState) -> List[SyncEntry]:
        ret = []
        found = False
        for e1 in s1.get_all():
            e1: SyncEntry
            for e2 in s2.get_all():
                e2: SyncEntry
                if e1.serialize() == e2.serialize():
                    found = True
            if not found:
                ret.append(e1)
        return ret

    missing1 = compare_states(cs1.state, cs2.state)
    missing2 = compare_states(cs2.state, cs1.state)
    for e in missing1:
        print(f"entry in 1 not found in 2 {e.pretty()}")
    for e in missing2:
        print(f"entry in 2 not found in 1 {e.pretty()}")

    assert not missing1
    assert not missing2
    not_dirty(cs1.state)
    new_cursor = cs1.emgrs[0].state.storage_get_cursor(cs1.emgrs[0]._cursor_tag)
    log.debug("cursor=%s %s", old_cursor, new_cursor)
    assert new_cursor is not None
    assert old_cursor != new_cursor


@pytest.mark.parametrize("drain", [None, LOCAL, REMOTE])
def test_sync_already_there(cs, drain: int):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    rinfo2 = cs.providers[REMOTE].create(remote_path1, BytesIO(b"hello"), None)

    if drain is not None:
        # one of the event managers is not reporting events
        cs.emgrs[drain]._drain()

    # fill up the state table
    cs.do()

    # all changes processed
    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo1.hash == rinfo1.hash

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")


@pytest.mark.parametrize("drain", [LOCAL, REMOTE])
def test_sync_already_there_conflict(cs, drain: int):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    rinfo2 = cs.providers[REMOTE].create(remote_path1, BytesIO(b"goodbye"), None)

    if drain is not None:
        # one of the event managers is not reporting events
        cs.emgrs[drain]._drain()

    # fill up the state table
    cs.do()

    # all changes processed
    cs.run(until=lambda: not cs.state.has_changes(), timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo1.hash == rinfo1.hash

    assert cs.providers[LOCAL].info_path(local_path1 + ".conflicted") or cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")
