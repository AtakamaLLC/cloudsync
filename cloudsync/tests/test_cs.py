from io import BytesIO
import logging
from threading import Lock
from typing import Dict, Any, Tuple

import pytest

from cloudsync import CloudSync, SyncState, Storage, LOCAL, REMOTE

from .test_sync import WaitFor, RunUntilHelper

log = logging.getLogger(__name__)


class MockStorage(Storage):  # Does not actually persist the data... but it's just a mock
    top_lock = Lock()
    lock_dict = dict()

    def __init__(self, storage_dict: Dict[str, Dict[int, bytes]]):
        self.storage_dict = storage_dict
        self.cursor: int = 0  # the next eid

    def _get_internal_storage(self, tag: str) -> Tuple[Lock, Dict[int, bytes]]:
        with self.top_lock:
            lock: Lock = self.lock_dict.setdefault(tag, Lock())
        return lock, self.storage_dict.setdefault(tag, dict())

    def create(self, tag: str, serialization: bytes) -> Any:
        lock, storage = self._get_internal_storage(tag)
        with lock:
            current_index = self.cursor
            self.cursor += 1
            storage[current_index] = serialization
            return current_index

    def update(self, tag: str, serialization: bytes, eid: Any):
        lock, storage = self._get_internal_storage(tag)
        with lock:
            if eid not in storage:
                raise ValueError("id %s doesn't exist" % eid)
            storage[eid] = serialization

    def delete(self, tag: str, eid: Any):
        lock, storage = self._get_internal_storage(tag)
        with lock:
            if eid not in storage:
                raise ValueError("id %s doesn't exist" % eid)
            del storage[eid]

    def read_all(self, tag: str) -> Dict[Any, bytes]:
        lock, storage = self._get_internal_storage(tag)
        with lock:
            ret: Dict[Any, bytes] = storage.copy()
            return ret


@pytest.fixture(name="cs")
def fixture_cs(mock_provider_generator):
    def translate(to, path):
        if to == LOCAL:
            return "/local" + path.replace("/remote", "")

        if to == REMOTE:
            return "/remote" + path.replace("/local", "")

        raise ValueError()

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    cs = CloudSyncMixin((mock_provider_generator(), mock_provider_generator()), translate)

    yield cs

    cs.done()

@pytest.fixture(name="multi_cs")
def fixture_multi_cs(mock_provider_generator):
    storage_dict = dict()
    # storage1 = MockStorage("storage1", storage_dict)
    # storage2 = MockStorage("storage2", storage_dict)
    storage = MockStorage(storage_dict)


    # state1 = SyncState(storage1)
    # state2 = SyncState(storage2)

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    p1 = mock_provider_generator()
    p2 = mock_provider_generator()
    p3 = mock_provider_generator()

    def translate1(to, path):
        if to == LOCAL:
            return "/local1" + path.replace("/remote", "")

        if to == REMOTE:
            if "/local1" in path:
                return "/remote" + path.replace("/local1", "")
            return None

        raise ValueError()

    def translate2(to, path):
        if to == LOCAL:
            return "/local2" + path.replace("/remote", "")

        if to == REMOTE:
            if "/local2" in path:
                return "/remote" + path.replace("/local2", "")
            return None

        raise ValueError()

    cs1 = CloudSyncMixin((p1, p2), translate1, storage, "tag1")
    cs2 = CloudSyncMixin((p1, p3), translate2, storage, "tag2")

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

    cs1.run_until_found(
            (LOCAL, local_path11),
            (LOCAL, local_path21),
            (REMOTE, remote_path1),
            (REMOTE, remote_path2),
    timeout=2)

    cs1.run(until=lambda:not cs1.state.has_changes(), timeout=1)
    log.info("TABLE\n%s", cs1.state.pretty_print())

    assert len(cs1.state) == 5      # two dirs, 3 files, 1 never synced (local2 file)

    try:
        cs2.run_until_found(
                (LOCAL, local_path12),
                (LOCAL, local_path22),
                (REMOTE, remote_path1),
                (REMOTE, remote_path2),
        timeout=2)
    except TimeoutError:
        log.info("TABLE\n%s", cs2.state.pretty_print())
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
    cs2.run(until=lambda:not cs2.state.has_changes(), timeout=1)
    log.info("TABLE\n%s", cs2.state.pretty_print())

    assert len(cs2.state) == 6  # two dirs, 4 files, 2 never synced (local1 files)


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
    cs.run(until=lambda:not cs.state.has_changes(), timeout=1)
    log.info("TABLE\n%s", cs.state.pretty_print())

    assert len(cs.state) == 3
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
        found.append( (REMOTE, remote_path1) )

    cs.run_until_found(*found)
    cs.run(until=lambda:not cs.state.has_changes(), timeout=1)

def test_sync_create_delete_same_name(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    cs.run(until=lambda:not cs.state.has_changes(), timeout=2)

    rinfo = cs.providers[REMOTE].info_path(remote_path1)

    cs.emgrs[LOCAL].do()

    cs.providers[LOCAL].delete(linfo1.oid)

    cs.emgrs[LOCAL].do()

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))

    # run local event manager only... not sync
    cs.emgrs[LOCAL].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print(ignore_dirs=False))
    if cs.providers[LOCAL].oid_is_path:
        assert(len(cs.state) == 2)
    else:
        assert(len(cs.state) == 3)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda:not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print(ignore_dirs=False))
    assert(len(cs.state) == 2)

    assert not cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert not cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")


def test_sync_two_conflicts(cs):
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print(ignore_dirs=False))

    linfo1 = cs.providers[LOCAL].info_path(local_path1)
    rinfo1 = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.providers[REMOTE].delete(rinfo1.oid)

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))
    linfo2 = cs.providers[REMOTE].create(remote_path1, BytesIO(b"world"))

    # run event managers only... not sync
    cs.emgrs[LOCAL].do()
    cs.emgrs[REMOTE].do()

    log.info("TABLE 1\n%s", cs.state.pretty_print(ignore_dirs=False))
    if cs.providers[LOCAL].oid_is_path:
        # the local delete/create doesn't add entries
        assert(len(cs.state) == 2)
    else:
        assert(len(cs.state) == 4)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda:not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print(ignore_dirs=False))
    assert(len(cs.state) == 3)

    assert cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    assert cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")

    b1 = BytesIO()
    b2 = BytesIO()

    cs.providers[LOCAL].download_path(local_path1, b1)
    cs.providers[LOCAL].download_path(local_path1 + ".conflicted", b2)

    assert b1.getvalue() in (b'goodbye', b'world')
    assert b2.getvalue() in (b'goodbye', b'world')
    assert b1.getvalue() != b2.getvalue()

def test_sync_folder_conflicts_file(cs):
    remote_path1 = "/remote/stuff1"
    remote_path2 = "/remote/stuff1/under"
    local_path1 = "/local/stuff1"

    setup_remote_local(cs, "stuff1")

    log.info("TABLE 0\n%s", cs.state.pretty_print(ignore_dirs=False))

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

    log.info("TABLE 1\n%s", cs.state.pretty_print(ignore_dirs=False))
    assert(len(cs.state) == 5)

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    cs.run(until=lambda:not cs.state.has_changes(), timeout=1)

    log.info("TABLE 2\n%s", cs.state.pretty_print(ignore_dirs=False))
    assert(len(cs.state) == 4)

    local_conf = cs.providers[LOCAL].info_path(local_path1 + ".conflicted")
    remote_conf = cs.providers[REMOTE].info_path(remote_path1 + ".conflicted")
