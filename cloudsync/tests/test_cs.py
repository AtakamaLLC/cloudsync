from io import BytesIO
import logging
import pytest
from typing import List, Dict, Any
from unittest.mock import patch


from .fixtures import MockProvider, MockStorage, mock_provider_instance
from cloudsync.sync.sqlite_storage import SqliteStorage
from cloudsync import Storage, CloudSync, SyncState, SyncEntry, LOCAL, REMOTE, FILE, DIRECTORY, CloudFileExistsError, CloudTemporaryError
from cloudsync.types import IgnoreReason
from cloudsync.notification import Notification, NotificationType
from .fixtures import WaitFor, RunUntilHelper

log = logging.getLogger(__name__)

roots = ("/local", "/remote")


class CloudSyncMixin(CloudSync, RunUntilHelper):
    def __init__(self, *ar, **kw):
        super().__init__(*ar, **kw)
        # default for tests is no aging, feel free to change
        self.aging = 0


@pytest.fixture(name="cs_storage")
def fixture_cs_storage(mock_provider_generator, mock_provider_creator):
    storage_dict: Dict[Any, Any] = dict()
    storage = MockStorage(storage_dict)
    for cs in _fixture_cs(mock_provider_generator, mock_provider_creator, storage):
        yield cs, storage


@pytest.fixture(name="cs")
def fixture_cs(mock_provider_generator, mock_provider_creator):
    yield from _fixture_cs(mock_provider_generator, mock_provider_creator)


def _fixture_cs(mock_provider_generator, mock_provider_creator, storage=None):
    cs = CloudSyncMixin((mock_provider_generator(), mock_provider_creator(oid_is_path=False, case_sensitive=True)), roots, storage=storage, sleep=None)

    yield cs

    cs.done()


def make_cs(mock_provider_creator, left=(True, True), right=(True, True), storage=None):
    return CloudSyncMixin((mock_provider_creator(*left), mock_provider_creator(*right)), roots, storage=storage, sleep=None)


# multi local test has two local providers, each syncing up to the same folder on one remote provider.
#   this simulates two separate machines syncing up to a shared folder
@pytest.fixture(name="multi_local_cs")
def fixture_multi_local_cs(mock_provider_generator):
    storage_dict: Dict[Any, Any] = dict()
    storage = MockStorage(storage_dict)


    p1 = mock_provider_generator()  # local
    p2 = mock_provider_generator()  # local
    p3 = mock_provider_instance(oid_is_path=False, case_sensitive=True)  # remote (cloud) storage

    log.debug(f"p1 oip={p1.oid_is_path} cs={p1.case_sensitive}")
    log.debug(f"p2 oip={p2.oid_is_path} cs={p2.case_sensitive}")
    log.debug(f"p3 oip={p3.oid_is_path} cs={p3.case_sensitive}")

    cs1 = CloudSyncMixin((p1, p3), roots, storage, sleep=None)
    cs2 = CloudSyncMixin((p2, p3), roots, storage, sleep=None)

    yield cs1, cs2

    cs1.done()
    cs2.done()


# multi remote test has one local provider with two folders, and each of those folders
# syncs up with a folder on one of two remote providers.
@pytest.fixture(name="multi_remote_cs")
def fixture_multi_remote_cs(mock_provider_generator):
    storage_dict: Dict[Any, Any] = dict()
    storage = MockStorage(storage_dict)

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


def test_sync_rename_away(multi_remote_cs):
    cs1, cs2 = multi_remote_cs

    remote_parent = "/remote"
    remote_path = "/remote/stuff1"

    local_parent1 = "/local1"
    local_parent2 = "/local2"
    local_path11 = "/local1/stuff1"
    local_path21 = "/local2/stuff1"

    cs1.providers[LOCAL].mkdir(local_parent1)
    cs1.providers[REMOTE].mkdir(remote_parent)
    cs2.providers[LOCAL].mkdir(local_parent2)
    cs2.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs1.providers[LOCAL].create(local_path11, BytesIO(b"hello1"), None)

    assert linfo1

    cs1.run_until_found(
        (LOCAL, local_path11),
        (REMOTE, remote_path),
        timeout=2)

    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print(use_sigs=False))
    log.info("TABLE 2\n%s", cs2.state.pretty_print(use_sigs=False))

    assert len(cs1.state) == 2      # 1 dirs, 1 files

    # This is the meat of the test. renaming out of one cloud bed into another
    #   Which will potentially forget to sync up the delete to remote1, leaving
    #   the file there and also in remote2
    log.debug("here")
    linfo2 = cs1.providers[LOCAL].rename(linfo1.oid, local_path21)
    log.debug("here")
    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print(use_sigs=False))
    log.debug("here")
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)
    log.info("TABLE 2\n%s", cs2.state.pretty_print(use_sigs=False))
    log.debug("here")

    try:
        cs1.run_until_found(
            WaitFor(LOCAL, local_path11, exists=False),
            timeout=2)
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs2.run_until_found(
            (LOCAL, local_path21),
            timeout=2)
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs2.run_until_found(
            (REMOTE, remote_path),
            timeout=2)
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        # If renaming out of local1 didn't properly sync, the next line will time out
        cs1.run_until_found(
            WaitFor(REMOTE, remote_path, exists=False),
            timeout=2)
    except TimeoutError:
        log.info("Timeout: TABLE 1\n%s", cs1.state.pretty_print())
        log.info("Timeout: TABLE 2\n%s", cs2.state.pretty_print())
        raise

    # let cleanups/discards/dedups happen if needed
    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)

    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 1   # 1 dir
    assert len(cs2.state) == 2   # 1 file and 1 dir


def test_sync_multi_local_rename_conflict(multi_local_cs):
    cs1, cs2 = multi_local_cs

    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff2"
    local_path1 = "/local/stuff1"
    local_path2 = "/local/stuff2"

    cs1_parent_oid = cs1.providers[LOCAL].mkdir(local_parent)
    cs2_parent_oid = cs2.providers[LOCAL].mkdir(local_parent)
    cs1.providers[REMOTE].mkdir(remote_parent)  # also creates on cs2[REMOTE]
    linfo1 = cs1.providers[LOCAL].create(local_path1, BytesIO(b"hello1"), None)
    linfo2 = cs2.providers[LOCAL].create(local_path2, BytesIO(b"hello2"), None)

    # Allow file1 to copy up to the cloud
    try:
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)  # file1 up
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)  # file2 up and file1 down
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)  # file2 down
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs1.run_until_found(
            (LOCAL, local_path1),
            (LOCAL, local_path2),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
            timeout=2)
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())
        cs2.run_until_found(
            (LOCAL, local_path1),
            (LOCAL, local_path2),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
            timeout=2)
    except TimeoutError:
        raise
    finally:
        log.info("TABLE 1\n%s", cs1.state.pretty_print())
        log.info("TABLE 2\n%s", cs2.state.pretty_print())

    # test file rename conflict
    other_linfo1 = cs2.providers[LOCAL].info_path(local_path1)

    cs1.providers[LOCAL].rename(linfo1.oid, local_path1 + "a")  # rename 'stuff1' to 'stuff1a'
    cs2.providers[LOCAL].rename(other_linfo1.oid, local_path1 + "b")  # rename 'stuff1' to 'stuff1b'

    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)  # let rename 'stuff1a' sync to cloud
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)  # try to sync 'stuff1b' rename. Conflict?
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())
    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)  # if cloud changed, let the change come down
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())

    # let cleanups/discards/dedups happen if needed
    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())
    a1 = cs1.providers[LOCAL].exists_path(local_path1 + "a")
    a2 = cs2.providers[LOCAL].exists_path(local_path1 + "a")
    b1 = cs1.providers[LOCAL].exists_path(local_path1 + "b")
    b2 = cs2.providers[LOCAL].exists_path(local_path1 + "b")
    dir1 = [x.name for x in cs1.providers[LOCAL].listdir(cs1_parent_oid)]
    dir2 = [x.name for x in cs2.providers[LOCAL].listdir(cs2_parent_oid)]
    log.debug("cs1=%s", dir1)
    log.debug("cs2=%s", dir2)
    assert a1 == a2  # either stuff1a exists on both providers, or neither
    assert b1 == b2  # either stuff1b exists on both providers, or neither

    assert all("conflicted" not in x for x in dir1)
    assert all("conflicted" not in x for x in dir2)


def test_sync_multi_local(multi_local_cs):
    cs1, cs2 = multi_local_cs

    local_parent = "/local"
    remote_parent = "/remote"

    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff2"

    local_path1 = "/local/stuff1"
    local_path2 = "/local/stuff2"

    cs1.providers[LOCAL].mkdir(local_parent)
    cs2.providers[LOCAL].mkdir(local_parent)
    cs1.providers[REMOTE].mkdir(remote_parent)  # also creates on cs2[REMOTE]

    linfo1 = cs1.providers[LOCAL].create(local_path1, BytesIO(b"hello1"), None)
    linfo2 = cs2.providers[LOCAL].create(local_path2, BytesIO(b"hello2"), None)
    # rinfo1 = cs1.providers[REMOTE].create(remote_path2, BytesIO(b"hello3"), None)
    # rinfo2 = cs2.providers[REMOTE].create(remote_path2, BytesIO(b"hello4"), None)

    assert linfo1 and linfo2 # and rinfo1 and rinfo2

    # Allow file1 to copy up to the cloud
    try:
        cs1.run_until_found(
            (LOCAL, local_path1),
            (REMOTE, remote_path1),
            timeout=2)
    except TimeoutError:
        log.info("Timeout: TABLE 1\n%s", cs1.state.pretty_print())
        log.info("Timeout: TABLE 2\n%s", cs2.state.pretty_print())
        raise

    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 2, cs1.state.pretty_print()      # 1 dirs, 1 files (haven't gotten the second file yet)

    # Allow file2 to copy up to the cloud, and to sync file1 down from the cloud to local2
    try:
        cs2.run_until_found(
            (LOCAL, local_path1),
            (LOCAL, local_path2),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
            timeout=2)
    except TimeoutError:
        log.info("Timeout: TABLE 1\n%s", cs1.state.pretty_print())
        log.info("Timeout: TABLE 2\n%s", cs2.state.pretty_print())
        raise

    linfo1 = cs1.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs1.providers[REMOTE].info_path(remote_path1)
    linfo2 = cs2.providers[LOCAL].info_path(local_path2)
    rinfo2 = cs2.providers[REMOTE].info_path(remote_path2)

    assert linfo1.oid
    assert linfo2.oid
    assert rinfo1.oid
    assert rinfo2.oid
    assert linfo1.hash == rinfo1.hash
    assert linfo2.hash == rinfo2.hash

    assert len(cs1.state) == 2, cs1.state.pretty_print()  # still the same as before
    assert len(cs2.state) == 3, cs2.state.pretty_print()  # cs2 now has file1 and file2, plus the dir

    # Allow file2 to sync down to local1
    try:
        cs1.run_until_found(
            (LOCAL, local_path1),
            (LOCAL, local_path2),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
            timeout=2)
    except TimeoutError:
        log.info("Timeout: TABLE 1\n%s", cs1.state.pretty_print())
        log.info("Timeout: TABLE 2\n%s", cs2.state.pretty_print())
        raise

    # let cleanups/discards/dedups happen if needed
    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)
    log.info("TABLE\n%s", cs2.state.pretty_print())


def test_sync_multi_remote(multi_remote_cs):
    cs1, cs2 = multi_remote_cs

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

    cs1.run(until=lambda: not cs1.state.changeset_len, timeout=1)
    log.info("TABLE 1\n%s", cs1.state.pretty_print())
    log.info("TABLE 2\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 3      # 1 dirs, 2 files, 1 never synced (local2 file)

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
    cs2.run(until=lambda: not cs2.state.changeset_len, timeout=1)
    log.info("TABLE\n%s", cs2.state.pretty_print())

    assert len(cs1.state) == 3
    assert len(cs2.state) == 3


def test_cs_basic(cs):
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

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    linfo2 = cs.providers[LOCAL].info_path(local_path2)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo2.oid
    assert rinfo1.oid

    bio = BytesIO()
    cs.providers[REMOTE].download(rinfo1.oid, bio)
    assert bio.getvalue() == b'hello'

    bio = BytesIO()
    cs.providers[LOCAL].download(linfo2.oid, bio)
    assert bio.getvalue() == b'hello2'

    assert linfo2.hash == rinfo2.hash
    assert linfo1.hash == rinfo1.hash

    assert not cs.providers[LOCAL].info_path(local_path2 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    # let cleanups/discards/dedups happen if needed
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    log.info("TABLE 2\n%s", cs.state.pretty_print())

    assert len(cs.state) == 3
    assert not cs.state.changeset_len


def setup_remote_local(cs, *names, content=b'hello'):
    remote_parent = "/remote"
    local_parent = "/local"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    found = []
    ret = []
    if type(content) is bytes:
        content = [content]*len(names)

    for i, name in enumerate(names):
        is_dir = name.endswith("/")
        name = name.strip("/")

        remote_path1 = "/remote/" + name
        local_path1 = "/local/" + name
        if "/" in name:
            local_dir1 = "/local/" + cs.providers[REMOTE].dirname(name)
            cs.providers[LOCAL].mkdir(local_dir1)
        if is_dir:
            cs.providers[LOCAL].mkdir(local_path1)
        else:
            cs.providers[LOCAL].create(local_path1, BytesIO(content[i]))
        found.append((REMOTE, remote_path1))
        ret.append((local_path1, remote_path1))

    cs.run_until_found(*found)
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    return ret


# pass in local/remote pairs
def get_infos(cs, *paths):
    log.info("infos %s", paths)
    if type(paths[0]) is str:
        # user passed in even number of paths
        assert len(paths) % 2 == 0
        paths = tuple([(paths[i+0], paths[i+1]) for i in range(0, len(paths), 2)])
        flat = True
    elif len(paths) == 1:
        paths = paths[0]
        flat = False
    else:
        raise ValueError("either pass paths, or a list of tuples")

    ret = []
    for tup in paths:
        (local, remote) = tup
        li = cs.providers[LOCAL].info_path(tup[LOCAL])
        ri = cs.providers[REMOTE].info_path(tup[REMOTE])
        li.side = LOCAL
        ri.side = REMOTE
        if flat:
            ret.append(li)
            ret.append(ri)
        else:
            ret.append((li, ri))
    return ret


@pytest.mark.repeat(4)
def test_cs_create_delete_same_name(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    cs.run(until=lambda: not cs.state.changeset_len, timeout=2)

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

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    # local and remote dirs can be disjoint
#    assert(len(cs.state) == 3 or len(cs.state) == 2)

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    rinfo = cs.providers[REMOTE].info_path(remote_path1)
    bio = BytesIO()
    cs.providers[REMOTE].download(rinfo.oid, bio)
    assert bio.getvalue() == b'goodbye'


# this test used to fail about 2 out of 10 times because of embracing a change that *wasn't properly indexed*
# it covers cases where events arrive in unexpected orders... could be possible to get the same coverage
# with a more deterministic version
@pytest.mark.repeat(10)
def test_cs_create_delete_same_name_heavy(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    import time, threading

    def creator():
        i = 0
        while i < 10:
            try:
                linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"file" + bytes(str(i),"utf8")))
                i += 1
            except CloudFileExistsError:
                linfo1 = cs.providers[LOCAL].info_path(local_path1)
                if linfo1:
                    cs.providers[LOCAL].delete(linfo1.oid)
            time.sleep(0.01)

    def done():
        bio = BytesIO()
        rinfo = cs.providers[REMOTE].info_path(remote_path1)
        if rinfo:
            cs.providers[REMOTE].download(rinfo.oid, bio)
            return bio.getvalue() == b'file' + bytes(str(9),"utf8")
        return False

    thread = threading.Thread(target=creator, daemon=True)
    thread.start()

    cs.run(until=done, timeout=3)

    thread.join()

    assert done()

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

def test_cs_rename_heavy(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_sub = "/remote/sub"
    local_sub = "/local/sub"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"
    remote_path2 = "/remote/sub/stuff1"
    local_path2 = "/local/sub/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].mkdir(local_sub)
    cs.providers[REMOTE].mkdir(remote_sub)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"file"))

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("TABLE 1\n%s", cs.state.pretty_print())


    import time, threading

    oid = linfo1.oid
    done = False
    ok = True
    def mover():
        nonlocal done
        nonlocal oid
        nonlocal ok
        for _ in range(10):
            try:
                oid = cs.providers[LOCAL].rename(oid, local_path2)
                oid = cs.providers[LOCAL].rename(oid, local_path1)
                time.sleep(0.001)
            except Exception as e:
                log.exception(e)
                ok = False
        done = True

    thread = threading.Thread(target=mover, daemon=True)
    thread.start()

    cs.run(until=lambda: done, timeout=3)

    thread.join()

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.do()

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    log.info("TABLE 3\n%s", cs.state.pretty_print())

    assert ok
    assert cs.providers[REMOTE].info_path(remote_path1)


def test_del_create_conflict(cs):
    ((local_path1, remote_path1),) = setup_remote_local(cs, "stuff1")

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
        assert(len(cs.state) == 4)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    # conflicted files are discarded, not in table
    log.info("TABLE 2\n%s", cs.state.pretty_print())
    assert(len(cs.state) == 2)

    assert cs.providers[LOCAL].info_path(local_path1 + ".conflicted") or cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    b1 = BytesIO()
    b2 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, b1)
    cs.providers[LOCAL].download_path(local_path1 + ".conflicted", b2)

    assert b1.getvalue() in (b'goodbye', b'world')
    assert b2.getvalue() in (b'goodbye', b'world')
    assert b1.getvalue() != b2.getvalue()


def test_conflict_merge_twice(cs):
    ((local_path1, remote_path1),) = setup_remote_local(cs, "stuff1")

    cs.smgr._resolve_conflict = lambda f1, f2: (BytesIO(f1.read() + b"merged"), False)

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].upload(linfo1.oid, BytesIO(b"goodbye"))
    cs.providers[REMOTE].upload(rinfo1.oid, BytesIO(b"world"))

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    l1 = BytesIO()
    r1 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, l1)
    cs.providers[REMOTE].download_path(remote_path1, r1)

    assert l1.getvalue() == b'worldmerged'
    assert r1.getvalue() == b'worldmerged'

    cs.providers[LOCAL].upload(linfo1.oid, BytesIO(b"goodbye2"))
    cs.providers[REMOTE].upload(rinfo1.oid, BytesIO(b"world2"))

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    l1 = BytesIO()
    r1 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, l1)
    cs.providers[REMOTE].download_path(remote_path1, r1)

    assert l1.getvalue() == b'world2merged'
    assert r1.getvalue() == b'world2merged'


@pytest.mark.repeat(10)
def test_cs_subdir_rename(cs):
    local_dir = "/local/a"
    local_base = "/local/a/stuff"
    local_dir2 = "/local/b"
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


def test_cs_rename_over(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    fn1 = "hello1"
    fn2 = "hello2"
    local_path1 = cs.providers[LOCAL].join(local_parent, fn1)  # "/local/hello1"
    local_path2 = cs.providers[LOCAL].join(local_parent, fn2)  # "/local/hello2"
    remote_path1 = cs.providers[REMOTE].join(remote_parent, fn1)  # "/remote/hello1"
    remote_path2 = cs.providers[REMOTE].join(remote_parent, fn2)  # "/remote/hello2"

    lpoid = cs.providers[LOCAL].mkdir(local_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(local_path1.encode('utf-8')))
    linfo2 = cs.providers[LOCAL].create(local_path2, BytesIO(local_path1.encode('utf-8')))

    cs.run_until_found((REMOTE, remote_path1), (REMOTE, remote_path2),  timeout=2)

    log.info("TABLE 1\n" + cs.state.pretty_print(use_sigs=False))
    # rename a file over another file by deleting the target and doing the rename in quick succession
    cs.providers[LOCAL].delete(linfo2.oid)
    cs.providers[LOCAL].rename(linfo1.oid, local_path2)

    log.info("TABLE 2\n" + cs.state.pretty_print(use_sigs=False))
    cs.run_until_found(WaitFor(side=REMOTE, path=remote_path1, exists=False),  timeout=2)
    log.info("TABLE 3\n%s", cs.state.pretty_print(use_sigs=False))

    # check the contents to make sure that path2 has path1's content
    new_oid = cs.providers[REMOTE].info_path(remote_path2).oid
    contents = BytesIO()
    cs.providers[REMOTE].download(new_oid, contents)
    assert contents.getvalue() == local_path1.encode('utf-8')

    # check that the folders each have only one file, and that it's path2
    rpoid = cs.providers[REMOTE].info_path(remote_parent).oid
    ldir = list(cs.providers[LOCAL].listdir(lpoid))
    rdir = list(cs.providers[REMOTE].listdir(rpoid))
    log.debug("ldir = %s", ldir)
    log.debug("rdir = %s", rdir)
    assert len(ldir) == 1
    assert ldir[0].path == local_path2
    assert len(rdir) == 1
    assert rdir[0].path == remote_path2


@pytest.mark.repeat(10)
@pytest.mark.parametrize("use_prio", [0, 1], ids=["norm", "prio"])
def test_cs_folder_conflicts_file(cs, use_prio):
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff1/under"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    if use_prio:
        def prio(side, path):
            # for whatever reason, prioritize this
            # it shouldn't mess anything up, esp with parent-conflict things
            if path == "/remote/stuff1/under" or path == "/local/stuff1/under":
                return -10
            return 0
        cs.prioritize = prio

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.providers[REMOTE].delete(rinfo1.oid)

    cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))
    cs.providers[REMOTE].mkdir(remote_path1)
    cs.providers[REMOTE].create(remote_path2, BytesIO(b"world"))

    # run event managers only... not sync
    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print())
    if cs.providers[LOCAL].oid_is_path:
        # there won't be 2 rows for /local/stuff1 is oid_is_path
        assert(len(cs.state) == 4)
        locs = cs.state.lookup_path(LOCAL, local_path1)
        assert locs and len(locs) == 1
#        loc = locs[0]
#        assert loc[LOCAL].otype == FILE
#        assert loc[REMOTE].otype == DIRECTORY
    else:
        # deleted /local/stuff, remote/stuff, remote/stuff/under, lcoal/stuff, /local
        assert(len(cs.state) == 5)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())
    assert(len(cs.state) == 4 or len(cs.state) == 3)

    local_conf = cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    remote_conf = cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    assert local_conf and not remote_conf

    # file was moved out of the way for the folder
    assert local_conf.otype == FILE

    # folder won
    local_conf = cs.providers[LOCAL].info_path(local_path1)
    assert local_conf.otype == DIRECTORY


@pytest.fixture(params=[(MockStorage, dict()), (SqliteStorage, 'file::memory:?cache=shared')],
                ids=["mock_storage", "sqlite_storage"],
                name="storage"
                )
def storage_fixture(request):
    return request.param


def test_storage(storage):
    storage_class = storage[0]
    storage_mechanism = storage[1]

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    p1 = MockProvider(oid_is_path=False, case_sensitive=True)
    p2 = MockProvider(oid_is_path=False, case_sensitive=True)

    storage1: Storage = storage_class(storage_mechanism)
    cs1: CloudSync = CloudSyncMixin((p1, p2), roots, storage1, sleep=None)
    cs1.do()
    old_cursor = cs1.emgrs[0].state.storage_get_data(cs1.emgrs[0]._cursor_tag)
    assert old_cursor is not None
    log.debug("cursor=%s", old_cursor)

    test_cs_basic(cs1)  # do some syncing, to get some entries into the state table

    storage2 = storage_class(storage_mechanism)
    cs2: CloudSync = CloudSyncMixin((p1, p2), roots, storage2, sleep=None)

    log.debug(f"state1 = {cs1.state.entry_count()}\n{cs1.state.pretty_print()}")
    log.debug(f"state2 = {cs2.state.entry_count()}\n{cs2.state.pretty_print()}")

    def not_dirty(s: SyncState):
        return not s._dirtyset

    def compare_states(s1: SyncState, s2: SyncState) -> List[SyncEntry]:
        ret = []
        found = False
        e1: SyncEntry
        for e1 in s1.get_all():
            e2: SyncEntry
            for e2 in s2.get_all():
                if e1.serialize() == e2.serialize():
                    found = True
            if not found:
                ret.append(e1)
        return ret

    not_dirty(cs1.state)

    missing1 = compare_states(cs1.state, cs2.state)
    missing2 = compare_states(cs2.state, cs1.state)

    for e in missing1:
        log.debug(f"entry in 1 not found in 2\n{e.pretty()}")
    for e in missing2:
        log.debug(f"entry in 2 not found in 1\n{e.pretty()}")

    if missing1 or missing2:
        log.debug("TABLE 1\n%s", cs1.state.pretty_print())
        log.debug("TABLE 2\n%s", cs2.state.pretty_print())

    assert not missing1
    assert not missing2
    new_cursor = cs1.emgrs[0].state.storage_get_data(cs1.emgrs[0]._cursor_tag)
    log.debug("cursor=%s %s", old_cursor, new_cursor)
    assert new_cursor is not None
    assert old_cursor != new_cursor

    before_forget = storage2.read_all()
    log.info("tags = %s", before_forget.keys())
    log.debug("before = %s", len(before_forget))
    assert len(before_forget) > 0
    cs2.forget()
    after_forget = storage2.read_all()
    log.debug("after = %s\n%s", len(after_forget), after_forget)
    assert len(after_forget) == 0


@pytest.mark.parametrize("drain", [None, LOCAL, REMOTE])
def test_cs_already_there(cs, drain: int):
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
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo1.hash == rinfo1.hash

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")


@pytest.mark.parametrize("drain", [LOCAL, REMOTE])
def test_cs_already_there_conflict(cs, drain: int):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    cs.providers[REMOTE].create(remote_path1, BytesIO(b"goodbye"), None)

    if drain is not None:
        # one of the event managers is not reporting events
        cs.emgrs[drain]._drain()

    # fill up the state table
    cs.do()

    # all changes processed
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo1.hash == rinfo1.hash

    assert cs.providers[LOCAL].info_path(local_path1 + ".conflicted") or cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")


def test_conflict_recover(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    remote_path2 = "/remote/new_path"
    local_path2 = "/local/new_path"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    cs.providers[REMOTE].create(remote_path1, BytesIO(b"goodbye"), None)

    # fill up the state table
    cs.do()

    # all changes processed
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    assert linfo1.hash == rinfo1.hash

    local_conflicted_path = local_path1 + ".conflicted"
    remote_conflicted_path = remote_path1 + ".conflicted"
    local_conflicted = cs.providers[LOCAL].info_path(local_conflicted_path)
    remote_conflicted = cs.providers[REMOTE].info_path(remote_conflicted_path)

    log.info("CONFLICTED TABLE\n%s", cs.state.pretty_print())

    # Check that exactly one of the files is present
    assert bool(local_conflicted) or bool(remote_conflicted)
    assert bool(local_conflicted) != bool(remote_conflicted)

    log.info("BEFORE RENAME AWAY\n%s", cs.state.pretty_print())

    # Rename the conflicted file to something new
    if local_conflicted:
        cs.providers[LOCAL].rename(local_conflicted.oid, local_path2)
    else:
        cs.providers[REMOTE].rename(remote_conflicted.oid, remote_path2)

    # fill up the state table
    cs.do()

    # all changes processed
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("AFTER RENAME AWAY\n%s", cs.state.pretty_print())

    local_conflicted = cs.providers[LOCAL].info_path(local_conflicted_path)
    remote_conflicted = cs.providers[REMOTE].info_path(remote_conflicted_path)

    assert not bool(local_conflicted) and not bool(remote_conflicted)

    local_new = cs.providers[LOCAL].info_path(local_path2)
    remote_new = cs.providers[REMOTE].info_path(remote_path2)

    assert bool(local_new) and bool(remote_new)


def test_conflict_recover_modify(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    remote_path2 = "/remote/new_path"
    local_path2 = "/local/new_path"

    # Create a clear-cut conflict
    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)
    cs.providers[REMOTE].create(remote_path1, BytesIO(b"goodbye"), None)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)
    assert linfo1.hash == rinfo1.hash

    local_conflicted_path = local_path1 + ".conflicted"
    remote_conflicted_path = remote_path1 + ".conflicted"
    local_conflicted = cs.providers[LOCAL].info_path(local_conflicted_path)
    remote_conflicted = cs.providers[REMOTE].info_path(remote_conflicted_path)

    log.info("CONFLICTED TABLE\n%s", cs.state.pretty_print())

    # Check that exactly one of the files is present
    assert bool(local_conflicted) or bool(remote_conflicted)
    assert bool(local_conflicted) != bool(remote_conflicted)

    if local_conflicted:
        assert local_conflicted.hash != linfo1.hash
        old_hash = local_conflicted.hash
    else:
        assert remote_conflicted.hash != rinfo1.hash
        old_hash = remote_conflicted.hash

    # Write some new content
    log.info("BEFORE MODIFY\n%s", cs.state.pretty_print())
    new_content = BytesIO(b"new content pls ignore")
    if local_conflicted:
        new_hash = cs.providers[LOCAL].upload(local_conflicted.oid, new_content).hash
    else:
        new_hash = cs.providers[REMOTE].upload(remote_conflicted.oid, new_content).hash

    assert new_hash != old_hash

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("AFTER MODIFY\n%s", cs.state.pretty_print())
    local_conflicted = cs.providers[LOCAL].info_path(local_conflicted_path)
    remote_conflicted = cs.providers[REMOTE].info_path(remote_conflicted_path)
    assert bool(local_conflicted) or bool(remote_conflicted)
    assert bool(local_conflicted) != bool(remote_conflicted)

    # Rename the conflicted file to something new
    log.info("BEFORE RENAME AWAY\n%s", cs.state.pretty_print())

    if local_conflicted:
        cs.providers[LOCAL].rename(local_conflicted.oid, local_path2)
    else:
        cs.providers[REMOTE].rename(remote_conflicted.oid, remote_path2)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("AFTER RENAME AWAY\n%s", cs.state.pretty_print())
    local_conflicted = cs.providers[LOCAL].info_path(local_conflicted_path)
    remote_conflicted = cs.providers[REMOTE].info_path(remote_conflicted_path)
    assert not bool(local_conflicted) and not bool(remote_conflicted)

    # Check that the new path was uploaded
    local_new = cs.providers[LOCAL].info_path(local_path2)
    remote_new = cs.providers[REMOTE].info_path(remote_path2)
    assert bool(local_new) and bool(remote_new)
    assert local_new.hash == remote_new.hash

    # And now make sure that we're correctly processing new changes on the file
    newer_content = BytesIO(b"ok this is the last time fr")
    cs.providers[LOCAL].upload(local_new.oid, newer_content)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    local_newer = cs.providers[LOCAL].info_path(local_path2)
    remote_newer = cs.providers[REMOTE].info_path(remote_path2)
    assert bool(local_newer) and bool(remote_newer)
    assert local_newer.hash == remote_newer.hash


@pytest.mark.parametrize('right', (True, False), ids=["right_cs", "right_in"])
@pytest.mark.parametrize('left', (True, False), ids=["left_cs", "left_in"])
def test_cs_rename_folder_case(mock_provider_creator, left, right):
    cs = make_cs(mock_provider_creator, (True, left), (False, right))
    local_parent = "/local"
    remote_parent = "/remote"
    local_path1 = "/local/a"
    local_path2 = "/local/a/b"
    local_path3 = "/local/A"
    remote_path1 = "/remote/A"
    remote_path2 = "/remote/A/b"

    cs.providers[LOCAL].mkdir(local_parent)
    ldir = cs.providers[LOCAL].mkdir(local_path1)
    linfo = cs.providers[LOCAL].create(local_path2, BytesIO(b"hello"), None)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.debug("--- cs: %s ---", [e.case_sensitive for e in cs.providers])
    cs.providers[LOCAL]._log_debug_state()
    cs.providers[REMOTE]._log_debug_state()

    cs.providers[LOCAL].rename(ldir, local_path3)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)
    rinfo2 = cs.providers[REMOTE].info_path(remote_path2)

    assert rinfo1 and rinfo2

    assert rinfo1.path == remote_path1
    assert rinfo2.path == remote_path2

# TODO: important tests: 
#    1. events coming in for path updates for conflicted files.... we should note conflict oids, and not insert them
#    2. for oid_as_path... events coming in for old creations, long since deleted or otherwise overwritten (renamed away, etc)


def test_cs_disconnect(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    cs.providers[REMOTE].disconnect()

    assert not cs.providers[REMOTE].connected

    cs.run(until=lambda: cs.providers[REMOTE].connected, timeout=2)

    assert not cs.providers[REMOTE].info_path(remote_path1)

    cs.run_until_found((REMOTE, remote_path1))


def test_cs_rename_tmp(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_sub = "/remote/sub"
    local_sub = "/local/sub"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"
    remote_path2 = "/remote/sub/stuff1"
    local_path2 = "/local/sub/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].mkdir(local_sub)
    cs.providers[REMOTE].mkdir(remote_sub)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    import time, threading

    done = False
    ok = True

    def mover():
        nonlocal done
        nonlocal ok
        for i in range(10):
            try:
                log.info("create local")
                linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"file" + bytes(str(i), "utf8")))
                linfo2 = cs.providers[LOCAL].info_path(local_path2)
                if linfo2:
                    without_event = isinstance(cs.providers[LOCAL], MockProvider)
                    log.info("delete prev")
                    if without_event:
                        cs.providers[LOCAL]._delete(linfo2.oid, without_event=True)
                    else:
                        cs.providers[LOCAL].delete(linfo2.oid)
                log.info("rename local")
                cs.providers[LOCAL].rename(linfo1.oid, local_path2)
                time.sleep(0.001)
            except Exception as e:
                log.exception(e)
                ok = False
        done = True

    thread = threading.Thread(target=mover, daemon=True)
    thread.start()

    cs.run(until=lambda: done, timeout=3)

    thread.join()

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.do()

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1
           )
    log.info("TABLE 3\n%s", cs.state.pretty_print())

    assert ok
    assert cs.providers[REMOTE].info_path(remote_path2)
    assert not cs.providers[REMOTE].info_path(remote_path2 + ".conflicted")
    assert not cs.providers[LOCAL].info_path(local_path2 + ".conflicted")
    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")


def test_cursor(cs_storage):
    cs = cs_storage[0]
    storage = cs_storage[1]

    local_parent = "/local"
    remote_parent = "/remote"
    local_path1 = "/local/stuff1"
    local_path2 = "/local/stuff2"
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff2"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello1"), None)

    cs.run_until_found(
        (LOCAL, local_path1),
        (REMOTE, remote_path1),
        timeout=2)

    # let cleanups/discards/dedups happen if needed
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    log.info("TABLE\n%s", cs.state.pretty_print())
    assert len(cs.state) == 2
    assert not cs.state.changeset_len

    linfo1 = cs.providers[LOCAL].create(local_path2, BytesIO(b"hello2"), None)

    p1 = cs.providers[LOCAL]
    p2 = cs.providers[REMOTE]
    p1.current_cursor = None
    p2.current_cursor = None
    roots = cs.roots

    cs2 = CloudSyncMixin((p1, p2), roots, storage=storage, sleep=None)
    cs2.run_until_found(
        (LOCAL, local_path2),
        timeout=2)
    cs2.run_until_found(
        (REMOTE, remote_path2),
        timeout=2)
    cs2.done()

@pytest.mark.repeat(3)
def test_cs_rename_up(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_sub = "/remote/sub"
    local_sub = "/local/sub"
    remote_path1 = "/remote/sub/stuff1"
    local_path1 = "/local/sub/stuff1"
    remote_path2 = "/remote/stuff1"
    local_path2 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].mkdir(local_sub)
    cs.providers[REMOTE].mkdir(remote_sub)

    cs.do()
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"file"))
    linfo2 = cs.providers[LOCAL].create(local_path2, BytesIO(b"file"))
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1
            )

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    without_event = isinstance(cs.providers[LOCAL], MockProvider)
    if without_event:
        cs.providers[LOCAL]._delete(linfo2.oid, without_event=True)
    else:
        cs.providers[LOCAL].delete(linfo2.oid)
    cs.providers[LOCAL].rename(linfo1.oid, local_path2)
    cs.run_until_found(
            WaitFor(REMOTE, remote_path1, exists=False),
            WaitFor(REMOTE, remote_path2, exists=True),
            timeout=2)
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path2 + ".conflicted")
    assert not cs.providers[LOCAL].info_path(local_path2 + ".conflicted")
    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert cs.providers[REMOTE].info_path(remote_path2)

def test_many_small_files_mkdir_perf(cs):
    local_root = "/local"
    remote_root = "/remote"

    cs.providers[LOCAL].mkdir(local_root)
    cs.providers[REMOTE].mkdir(remote_root)
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    def make_files(dir_suffix: str, clear_before: bool):
        local_base = f"{local_root}/{dir_suffix}"
        local_file_base = f"{local_base}/file" + dir_suffix
        remote_base = f"{remote_root}/{dir_suffix}"
        remote_file_base = f"{remote_base}/file" + dir_suffix

        # Let's make some subdirs
        cs.providers[LOCAL].mkdir(local_base)

        # Optionally, give ourselves a clean slate before starting to process
        # all the file uploads. Since all the child file events rely on this
        # happening first, it's easy for performance issues to sneak in.
        if clear_before:
            cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

        # Upload 20 x 3 KiB files. The size and number shouldn't actually
        # matter.
        content = BytesIO(b"\0" * (3 * 1024))
        for i in range(20):
            local_file_name = local_file_base + str(i)
            linfo = cs.providers[LOCAL].create(local_file_name, content, None)
            assert linfo is not None

        cs.run(until=lambda: not cs.state.changeset_len, timeout=10)

        for i in range(20):
            rinfo = cs.providers[REMOTE].info_path(remote_file_base + str(i))
            assert rinfo is not None

    local_old_api = cs.providers[LOCAL]._api
    remote_old_api = cs.providers[REMOTE]._api

    # Count the number of API hits without the clean slate
    with patch.object(cs.providers[LOCAL], "_api",
                      side_effect=local_old_api) as local_no_clear, \
         patch.object(cs.providers[REMOTE], "_api",
                      side_effect=remote_old_api) as remote_no_clear:
        make_files("_no_clear", clear_before=False)

    # Count the number of API hits with the clean slate
    with patch.object(cs.providers[LOCAL], "_api",
                      side_effect=local_old_api) as local_clear, \
         patch.object(cs.providers[REMOTE], "_api",
                      side_effect=remote_old_api) as remote_clear:
        make_files("_clear", clear_before=True)

    # Check that the two are approximately the same
    assert abs(local_no_clear.call_count - local_clear.call_count) < 3
    assert abs(remote_no_clear.call_count - remote_clear.call_count) < 3


@pytest.mark.parametrize("shuffle", range(5), ids=list("shuff%s" % i if i else "ordered" for i in range(5)))
def test_cs_folder_conflicts_del(cs, shuffle):
    local_path1 = "/local/stuff1"
    local_path1_u = "/local/stuff1/under"
    remote_path1 = "/remote/stuff1"
    remote_path1_u = "/remote/stuff1/under"

    local_path2 = "/local/stuff2"
    local_path2_u = "/local/stuff2/under"
    remote_path2 = "/remote/stuff2"
    remote_path2_u = "/remote/stuff2/under"
    remote_path3 = "/remote/stuff3"
    remote_path3_u = "/remote/stuff3/under"

    if shuffle:
        cs.state.shuffle = True

    cs.providers[LOCAL].mkdir("/local")
    linfo1_oid = cs.providers[LOCAL].mkdir(local_path1)
    cs.providers[LOCAL].create(local_path1_u, BytesIO(b'fff'))

    cs.run_until_found(
        (REMOTE, remote_path1),
        (REMOTE, remote_path1_u),
        timeout=2)

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    # rename both at same time
    cs.providers[LOCAL].rename(linfo1_oid, local_path2)
    rinfo3_oid = cs.providers[REMOTE].rename(rinfo1.oid, remote_path3)

    # then delete remote
    rinfo3_u = cs.providers[REMOTE].info_path(remote_path3_u)
    cs.providers[REMOTE].delete(rinfo3_u.oid)
    cs.providers[REMOTE].delete(rinfo3_oid)

    cs.run(until=lambda: cs.state.changeset_len == 0, timeout=1)
    log.info("TABLE 1\n%s", cs.state.pretty_print())

    assert cs.state.changeset_len == 0

    # either a deletion happened or a rename... whatever
    # but at least it doesn't time out or crash

    if cs.providers[REMOTE].info_path(remote_path2_u):
        assert cs.providers[LOCAL].info_path(local_path2_u)
        assert cs.providers[REMOTE].info_path(remote_path2)
    else:
        assert not cs.providers[LOCAL].info_path(local_path2_u)
        if not cs.providers[LOCAL].oid_is_path:
            assert not cs.providers[LOCAL].info_path(local_path2)


def test_api_hit_perf(cs):
    local_root = "/local"
    remote_root = "/remote"
    local_file_base = f"{local_root}/file"
    remote_file_base = f"{remote_root}/file"

    cs.providers[LOCAL].mkdir(local_root)
    cs.providers[REMOTE].mkdir(remote_root)
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    remote_old_api = cs.providers[REMOTE]._api

    import traceback

    remote_counter = 0

    def remote_tb_api(*a, **kw):
        nonlocal remote_counter
        remote_counter += 1
        log.debug("API HIT %s", traceback.format_stack(limit=7))
        remote_old_api(*a, **kw)

    # upload 10 files
    content = BytesIO(b"hello")
    prev_oid = None
    for i in range(10):
        local_file_name = local_file_base + str(i)
        info = cs.providers[LOCAL].create(local_file_name, content, None)
        if prev_oid:
            cs.providers[LOCAL].delete(prev_oid)
        prev_oid = cs.providers[LOCAL].rename(info.oid, local_file_base)

    cs.emgrs[0].do()

    log.debug("RUNNING")

    with patch.object(cs.providers[REMOTE], "_api",
                      side_effect=remote_tb_api):

        cs.run(until=lambda: not cs.state.changeset_len, timeout=2)

    assert abs(remote_counter) < 20

    for i in range(10):
        remote_file_name = remote_file_base + str(i)
        rinfo = cs.providers[REMOTE].info_path(remote_file_name)
        assert rinfo is None
    rinfo = cs.providers[REMOTE].info_path(remote_file_base)
    assert rinfo


def test_dir_delete_give_up(cs):
    # Local: dir with file inside, delete file then dir
    # Remote: at same time, add file to dir
    # Sometimes we'll process the remote file add before our dir delete, so we cannot
    # dir delete
    # In that case, we should not retry the dir delete forever
    local_parent = "/local"
    remote_parent = "/remote"
    local_dir = "/local/dir"
    remote_dir = "/remote/dir"
    local_f1 = "/local/dir/f1"
    remote_f1 = "/remote/dir/f1"
    local_f2 = "/local/dir/f2"
    remote_f2 = "/remote/dir/f2"

    # Setup, create initial dir and file
    lpoid = cs.providers[LOCAL].mkdir(local_parent)
    rpoid = cs.providers[REMOTE].mkdir(remote_parent)
    ldoid = cs.providers[LOCAL].mkdir(local_dir)
    lf1obj = cs.providers[LOCAL].create(local_f1, BytesIO(b"hello"), None)

    cs.run_until_found(
        (LOCAL, local_dir),
        (LOCAL, local_f1),
        (REMOTE, remote_dir),
        (REMOTE, remote_f1),
        timeout=2)

    # Delete local dir while adding file remotely
    cs.providers[LOCAL].delete(lf1obj.oid)
    cs.providers[LOCAL].delete(ldoid)
    cs.providers[REMOTE].create(remote_f2, BytesIO(b"goodbye"), None)

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    assert cs.state.changeset_len == 0
    ldir = list(cs.providers[LOCAL].listdir(lpoid))
    rdir = list(cs.providers[REMOTE].listdir(rpoid))

    # dirs should still exist on both sides
    assert len(rdir) == 1
    assert rdir[0].path == remote_dir
    assert len(ldir) == 1
    assert ldir[0].path == local_dir


@pytest.mark.parametrize("oidless", [True, False], ids=["oidless", "normal"])
def test_replace_dir(cs, oidless):
    local = cs.providers[LOCAL]
    remote = cs.providers[REMOTE]

    remote._oidless_folder_trash_events = oidless
    local.mkdir("/local")
    remote.mkdir("/remote")

    def get_oid(prov, path):
        return prov.info_path(path).oid

    # Make first set
    local.mkdir("/local/Test")
    local.create("/local/Test/Excel.xlsx", BytesIO(b"aaa"))

    # Make "copy" of files
    local.mkdir("/local/Test2")
    linfo = local.create("/local/Test2/Excel.xlsx", BytesIO(b"aab"))

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    # Now simulate a dir replace (e.g. shutil rmtree/rename)
    local.delete(get_oid(local, "/local/Test/Excel.xlsx"))
    local.delete(get_oid(local, "/local/Test"))
    local.rename(get_oid(local, "/local/Test2"), "/local/Test")

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)
    log.info("END TABLE\n%s", cs.state.pretty_print())

    # Check that the file got synced
    rinfo = remote.info_path("/remote/Test/Excel.xlsx")
    assert rinfo

    # Check that the *correct* file got synced
    assert linfo.hash == rinfo.hash

    # That was the important one, what follows are just checks for consistent
    # internal state

    # Check that there aren't any weird duplicate entries on the remote
    bad_rinfo_dir = remote.info_path("/remote/Test2")
    assert bad_rinfo_dir is None

    bad_rinfo_file = remote.info_path("/remote/Test2/Excel.xlsx")
    assert bad_rinfo_file is None

    # And do the same for local
    bad_linfo_dir = local.info_path("/local/Test2")
    assert bad_linfo_dir is None

    bad_linfo_file = local.info_path("/local/Test2/Excel.xlsx")
    assert bad_linfo_file is None

    assert not any("conflicted" in x.path for x in local.listdir_path("/local/Test"))
    assert not any("conflicted" in x.path for x in remote.listdir_path("/remote/Test"))


def test_out_of_space(cs):
    local = cs.providers[LOCAL]
    remote = cs.providers[REMOTE]

    remote._set_quota(1024)

    local.mkdir("/local")
    remote.mkdir("/remote")

    local.create("/local/foo", BytesIO(b'0' * 1025))

    cs.run(until=lambda: cs.in_backoff, timeout=0.25)

    log.info("END TABLE\n%s", cs.state.pretty_print())

    assert cs.in_backoff
    assert cs.state.changeset_len


@pytest.mark.parametrize("recover", [True, False])
def test_backoff(cs, recover):
    local = cs.providers[LOCAL]
    remote = cs.providers[REMOTE]

    local.mkdir("/local")
    remote.mkdir("/remote")

    local.create("/local/foo", BytesIO(b'0' * 1025))

    remote.disconnect()
    remote._creds = None

    cs.start(until=lambda: cs.smgr.in_backoff, timeout=1)
    cs.wait()

    log.info("START TABLE\n%s", cs.state.pretty_print())
    log.info("DISCONNECTED")

    if recover:
        remote._creds = "ok"
        log.info("RECONNECT %s", cs.smgr.in_backoff)
        cs.start(until=lambda: not cs.smgr.in_backoff, timeout=1)
        cs.wait()

    log.info("END TABLE\n%s", cs.state.pretty_print())

    if recover:
        assert not cs.in_backoff
        assert cs.state.changeset_len
    else:
        assert cs.smgr.in_backoff


def test_cs_prioritize(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = "/local/stuff1"
    remote_path1 = "/remote/stuff1"
    local_path2 = "/local/stuff2"
    remote_path2 = "/remote/stuff2"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    lp1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))
    rp2 = cs.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

    # aging 3 seconds... nothing should get processed
    cs.aging = 4

    # this should also prioritize the remote, even though the local doesn't exist
    def prio(side, path):
        if path == local_path2 or path == remote_path2:
            log.debug("PRIO RETURNING %s", path)
            return -1
        return 0

    cs.prioritize = prio

    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    ent1 = cs.state.lookup_oid(LOCAL, lp1.oid)
    ent2 = cs.state.lookup_oid(REMOTE, rp2.oid)
    assert ent1[LOCAL].changed > 0
    assert ent2[REMOTE].changed > 0

    # ensure ent2 is later... regardless of clock granularity
    ent2[REMOTE].changed = ent1[LOCAL].changed + 0.01

    prev_len = cs.state.changeset_len

    cs.do()

    # nothing is happening because aging is too long
    assert cs.state.changeset_len == prev_len


    log.info("BEFORE TABLE\n%s", cs.state.pretty_print())

    cs.run_until_found(
            (LOCAL, local_path2)
            )

    log.info("AFTER TABLE\n%s", cs.state.pretty_print())

    assert cs.providers[LOCAL].info_path(local_path2)
    assert not cs.providers[REMOTE].info_path(remote_path1)


MERGE = 2


@pytest.mark.parametrize("side_locked", [
    (LOCAL,  []),
    (LOCAL,  [LOCAL]),
    (REMOTE, []),
    (REMOTE, [REMOTE]),
    (MERGE,  []),
    (MERGE,  [LOCAL, REMOTE]),
    ], ids = ["loc", "loc-lock", "remote", "remote-lock", "merge", "merge-lock"])
def test_hash_mess(cs, side_locked):
    (side, locks) = side_locked
    local = cs.providers[LOCAL]
    remote = cs.providers[REMOTE]

    assert not remote.oid_is_path

    local.mkdir("/local")
    remote.mkdir("/remote")

    def get_oid(prov, path):
        return prov.info_path(path).oid

    # Make first set
    local.mkdir("/local/")
    linfo = local.create("/local/foo", BytesIO(b"aaa"))

    cs.run_until_found((REMOTE, "/remote/foo"))

    rinfo = remote.info_path("/remote/foo")

    renamed_path = ("/local/foo-l", "/remote/foo-r")

    local_oid = local.rename(linfo.oid, "/local/foo-l")
    remote_oid = remote.rename(rinfo.oid, "/remote/foo-r")
    local.upload(local_oid, BytesIO(b"zzz1"))
    remote.upload(remote_oid, BytesIO(b"zzz2"))


    f3 = BytesIO(b'merged')

    if side == LOCAL:
        cs.smgr._resolve_conflict = lambda f1, f2: (f1, False)
    elif side == REMOTE:
        cs.smgr._resolve_conflict = lambda f1, f2: (f2, False)
    elif side == MERGE:
        cs.smgr._resolve_conflict = lambda f1, f2: (f3, False)

    log.info("START TABLE\n%s", cs.state.pretty_print())

    if locks:
        def _called(msg):
            _called.count += 1                                  # type: ignore
            raise CloudTemporaryError("CALLED %s" % msg)

        _called.count = 0                                       # type: ignore

        with patch("cloudsync.tests.fixtures.mock_provider.CloudTemporaryError", new=_called):
            for locked in locks:
                cs.providers[locked]._locked_for_test.add(renamed_path[locked])
                log.info("lock set: %s", renamed_path[locked])
            cs.run(until=lambda: _called.count > 0, timeout=2)  # type: ignore
            for locked in locks:
                cs.providers[locked]._locked_for_test.discard(renamed_path[locked])

    cs.run(until=lambda: not cs.state.changeset_len, timeout=0.25)

    log.info("END TABLE\n%s", cs.state.pretty_print())

    l_r = local.info_path("/local/foo-r")
    l_l = local.info_path("/local/foo-l")
    r_l = remote.info_path("/remote/foo-l")
    r_r = remote.info_path("/remote/foo-r")

    assert l_r is not None or l_l is not None
    assert r_r is not None or r_l is not None
    assert bool(l_r) == bool(r_r)
    assert bool(r_l) == bool(l_l)



def test_temp_dropped(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"), None)

    orig_changed = cs.smgr.download_changed

    hit = False

    def new_changed(changed, sync):
        nonlocal hit
        orig_changed(changed, sync)
        hit = True
        return False

    cs.smgr.download_changed = new_changed

    log.debug("run until hit")

    cs.run(until=lambda: hit)

    log.info("TABLE\n%s", cs.state.pretty_print())

    import shutil
    shutil.rmtree(cs.smgr.tempdir)

    cs.smgr.download_changed = orig_changed

    cs.run_until_found(
        (REMOTE, remote_path1),
        timeout=2)


def test_unfile(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    local_path1 = "/local/stuff1"
    remote_path1 = "/remote/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.run_until_found(
        (REMOTE, remote_parent),
        timeout=1)

    # test 1
    log.debug("CREATE")
    info = cs.providers[REMOTE].create(remote_path1, BytesIO(b"hello"), None)
    log.debug("UNFILE")
    cs.providers[REMOTE]._unfile(info.oid)
    cs.run(until=lambda: cs.state.lookup_oid(REMOTE, info.oid).ignored != IgnoreReason.NONE, timeout=1)

    # test 2

    log.debug("CREATE")
    info = cs.providers[REMOTE].create(remote_path1, BytesIO(b"hello"), None)
    cs.run_until_found(
        (LOCAL, local_path1),
        timeout=2)

    log.info("START TABLE\n%s", cs.state.pretty_print())
    log.debug("UNFILE")
    cs.providers[REMOTE]._unfile(info.oid)
    cs.run_until_found(
        WaitFor(LOCAL, local_path1, exists=False),
        timeout=2)


@pytest.mark.parametrize("side", [LOCAL, REMOTE], ids=["local", "remote"])
def test_multihash_one_side_equiv(mock_provider_creator, side):
    def segment_hash(data):
        # two hashes.... one is mutable (notion of equivalence) the other causes conflicts (data change)
        return [hash(data[0:1]), hash(data[1:])]

    provs = (
        mock_provider_creator(oid_is_path=True, case_sensitive=False, hash_func=segment_hash),
        mock_provider_creator(oid_is_path=False, case_sensitive=False)
    )

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        def resolve_conflict(self, f1, f2):
            fhs = sorted((f1, f2), key=lambda a: a.side)

            log.info("custom resolver sides:%s/%s, sh:%s, sh:%s", f1.side, f2.side, f1.sync_hash, f2.sync_hash)

            if fhs[0].sync_hash:
                if fhs[0].hash[1] == fhs[0].sync_hash[1]:
                    log.info("local was equivalent to last sync... remote wins")
                    return (fhs[1], False)

                # last time i synced fh0 same as fh1
                other_sh = segment_hash(fhs[1].read())
                log.info("%s == %s", fhs[0].sync_hash, other_sh)
                if fhs[0].sync_hash[1] == other_sh[1]:
                    log.info("remote was equivalent to last sync... local wins")
                    return (fhs[0], False)

            return None

    cs = CloudSyncMixin(provs, roots, storage=None, sleep=None)

    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.providers[REMOTE].delete(rinfo1.oid)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"a-same"))
    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    if (side == LOCAL):
        linfo1 = cs.providers[LOCAL].upload(linfo1.oid, BytesIO(b"b-diff"))
        rinfo2 = cs.providers[REMOTE].upload(rinfo1.oid, BytesIO(b"c-same"))
    else:
        linfo1 = cs.providers[LOCAL].upload(linfo1.oid, BytesIO(b"c-same"))
        rinfo2 = cs.providers[REMOTE].upload(rinfo1.oid, BytesIO(b"b-diff"))

    # run event managers only... not sync
    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    # conflicted files are discarded, not in table
    log.info("TABLE 2\n%s", cs.state.pretty_print())
    assert(len(cs.state) == 2)

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted") \
        and not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    b1 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, b1)

    assert b1.getvalue() == b'b-diff'


@pytest.fixture(name="setup_offline_state", params=[True, False], ids=["path", "oid"])
def _setup_offline_state(request, mock_provider_creator):
    local_uses_path = request.param
    storage_dict: Dict[Any, Any] = dict()
    storage = MockStorage(storage_dict)

    providers = (mock_provider_creator(oid_is_path=local_uses_path, case_sensitive=True), mock_provider_creator(oid_is_path=False, case_sensitive=True))
    providers[LOCAL]._uses_cursor = False

    # all this setup is necessry, because we need the "_uses_cursor" flag to be false before the syncmgr is initalized
    cs = CloudSyncMixin(providers, roots, storage=storage, sleep=None)

    [(lp1, lp2)] = setup_remote_local(cs, "stuff1")

    li1, ri1 = get_infos(cs, lp1, lp2)
    assert li1.path == lp1

    assert cs.providers[LOCAL].current_cursor is None
    assert cs.emgrs[LOCAL].cursor is None

    yield cs, storage, li1, ri1

    cs.done()


def test_walk_carefully1(setup_offline_state):
    cs, storage, li1, ri1 = setup_offline_state

    # stuff that happened while i was away
    cs.providers[LOCAL].upload(li1.oid, BytesIO(b"changed-while-stopped"))
    cs.providers[REMOTE].rename(ri1.oid, "/remote/new-name")
    cs.emgrs[LOCAL]._drain()            # cursorless providers drop offline events on the floor

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    cs = CloudSyncMixin(cs.providers, cs.roots, storage=storage, sleep=None)
    cs.emgrs[LOCAL].cursor = None

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    b = BytesIO()
    cs.providers[REMOTE].download_path("/remote/new-name", b)
    assert b.getvalue() == b"changed-while-stopped"


def test_walk_carefully2(setup_offline_state):
    cs, storage, li1, ri1 = setup_offline_state

    if cs.providers[LOCAL].oid_is_path and not cs.providers[LOCAL]._uses_cursor:
        pytest.skip("offline events for cursorless path providers cannot be supported")

    log.info("TABLE 0\n%s", cs.state.pretty_print())
    # stuff that happened while i was away
    cs.providers[LOCAL].rename(li1.oid, "/local/new-name")
    cs.providers[REMOTE].upload(ri1.oid, BytesIO(b"changed-while-stopped"))
    cs.emgrs[LOCAL]._drain()        # cursorless providers drop offline events on the floor

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    cs = CloudSyncMixin(cs.providers, cs.roots, storage=storage, sleep=None)
    cs.emgrs[LOCAL].cursor = None

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    b = BytesIO()
    cs.providers[LOCAL].download_path("/local/new-name", b)
    assert b.getvalue() == b"changed-while-stopped"


def test_walk_carefully3(setup_offline_state):
    cs, storage, li1, ri1 = setup_offline_state

    # stuff that happened while i was away
    cs.providers[REMOTE].upload(ri1.oid, BytesIO(b"changed-while-stopped"))

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    cs = CloudSyncMixin(cs.providers, cs.roots, storage=storage, sleep=None)
    cs.emgrs[LOCAL].cursor = None

    log.info("TABLE 2\n%s", cs.state.pretty_print())

    cs.smgr.do()

    log.info("TABLE 3\n%s", cs.state.pretty_print())

    assert not cs.state.lookup_oid(LOCAL, li1.oid)[LOCAL].changed

    cs.run(until=lambda: not cs.state.changeset_len, timeout=1)

    b = BytesIO()
    cs.providers[LOCAL].download_path("/local/stuff1", b)
    assert b.getvalue() == b"changed-while-stopped"


def test_notify_bad_name(cs):
    setup_remote_local(cs)
    called = False

    def _handle(e: Notification):
        nonlocal called
        if e.ntype == NotificationType.FILE_NAME_ERROR:
            called = True
    cs.handle_notification = _handle

    local, remote = cs.providers
    remote._forbidden_chars = ['`']
    local.create('/local/bad`.txt', BytesIO(b'data'))
    cs.start(until=lambda: called, timeout=2)  # Need to use start() because the notification manager do() blocks
    log.debug("Now waiting")
    cs.wait()
    assert called
    cs.stop()


def test_notify_disconnect(cs):
    setup_remote_local(cs)
    called = False

    def _handle(e: Notification):
        nonlocal called
        if e.ntype == NotificationType.DISCONNECTED_ERROR:
            called = True
    cs.handle_notification = _handle

    local, remote = cs.providers
    remote._forbidden_chars = ['`']
    local.create('/local/bad.txt', BytesIO(b'data'))
    cs.providers[0].disconnect()
    cs.providers[0].reconnect = lambda: None  # TODO: Revisit this after authorization has been redesigned
    cs.start(until=lambda: called, timeout=2)  # Need to use start() because the notification manager do() blocks
    log.debug("Now waiting")
    cs.wait()
    assert called
    cs.stop()


def test_no_nsquare(cs):
    setup_remote_local(cs)

    apic = [0, 0]
    for side in (LOCAL, REMOTE):
        orig_api = cs.providers[side]._api

        def api(*a, **kw):
            apic[side] += 1
            orig_api(*a, **kw)

        cs.providers[side]._api = api

    # each normal sync can take up to 12 api hits
    normal = 12 * 24
    expect = normal * 1.5

    for i in range(12):
        for side, d in enumerate(roots):
            # these might get punted
            cs.providers[side].create(d + "/" + str(i), BytesIO(b'yo'))
        # clearing these successes shouldn't clear the punt counts of the others
        cs.providers[LOCAL].create(roots[LOCAL] + "/x" + str(i), BytesIO(b'yo'))

    # events all come in before processing....for simplicity
    cs.emgrs[0].do()
    cs.emgrs[1].do()

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    cs.run(until=lambda: not cs.state.changeset_len, timeout=10)

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    log.debug("APIC %s", apic)
    assert (apic[1] + apic[0]) < expect


def test_two_level_rename(cs):
    (local, remote) = cs.providers

    ret = setup_remote_local(cs, "a/", "a/fa1", "a/fa2", "a/b/", "a/b/fb1", "a/b/fb2")

    log.debug("setup ret == %s", ret)

    (
        (la, ra),
        (la1, ra1),
        (la2, ra2),
        (lb, rb),
        (lb1, rb1),
        (lb2, rb1),
    ) = get_infos(cs, ret)

    log.info("TABLE 0\n%s", cs.state.pretty_print())

    local.rename(lb.oid, "/local/a/c")
    local.rename(la.oid, "/local/d")

    cs.run(until=lambda: not cs.busy, timeout=3)

    log.info("TABLE 1\n%s", cs.state.pretty_print())

    assert local.info_path("/local/d/c/fb1")
    assert remote.info_path("/remote/d/c/fb1")
    assert local.info_path("/local/d/c/fb2")
    assert remote.info_path("/remote/d/c/fb2")

    assert not any("conflicted" in e.path for e in local.walk("/local"))
    assert not any("conflicted" in e.path for e in remote.walk("/remote"))


def test_reconn_after_disconn():
    (local, remote) = MockProvider(False, False), MockProvider(False, False)
    remote.disconnect()
    remote._creds = None
    cs = CloudSyncMixin((local, remote), roots, storage=None, sleep=None)
    local.mkdir("/local")

    # this forces the remote to fail connections forever
    called = False

    def _handle(e: Notification):
        nonlocal called
        if e.ntype == NotificationType.DISCONNECTED_ERROR:
            called = True
    cs.handle_notification = _handle        # type: ignore

    assert not remote.connected

    # it's ok to start a cs this way
    cs.start()
    cs.wait_until(lambda: called)

    # still ok....
    assert not remote.connected

    # syncs on reconnect
    remote._creds = {"ok":"ok"}
    remote.reconnect()

    # yay
    cs.wait_until_found((REMOTE, "/remote"))
    cs.stop()
