from io import BytesIO
import logging

import pytest

from cloudsync import CloudSync, SyncState, LOCAL, REMOTE

from .fixtures import MockProvider

from .test_sync import WaitFor, RunUntilHelper

log = logging.getLogger(__name__)

@pytest.fixture(name="cs")
def fixture_cs():
    state = SyncState()

    def translate(to, path):
        if to == LOCAL:
            return "/local" + path.replace("/remote", "")

        if to == REMOTE:
            return "/remote" + path.replace("/local", "")

        raise ValueError()

    class CloudSyncMixin(CloudSync, RunUntilHelper):
        pass

    cs = CloudSyncMixin((MockProvider(), MockProvider()), translate, state)

    yield cs

    cs.done()

def test_sync_basic(cs):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"
    remote_path2 = "/remote/stuff2"
    local_path2 = "/local/stuff2"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)
    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))
    rinfo2 = cs.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

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
    log.error("TABLE\n%s", cs.state.pretty_print())


def test_sync_conflict_delete(cs):
    remote_parent = "/remote"
    local_parent = "/local"
    remote_path1 = "/remote/stuff1"
    local_path1 = "/local/stuff1"

    cs.providers[LOCAL].mkdir(local_parent)
    cs.providers[REMOTE].mkdir(remote_parent)

    linfo1 = cs.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    cs.run_until_found((REMOTE, remote_path1), timeout=2)

    rinfo = cs.providers[REMOTE].info_path(remote_path1)

    cs.providers[LOCAL].delete(linfo1.oid)
    cs.emgrs[LOCAL].do()

    linfo2 = cs.providers[LOCAL].create(local_path1, BytesIO(b"goodbye"))

    cs.emgrs[LOCAL].do()

    cs.run(until=lambda: len(cs.state) == 3, timeout=2)
    log.error("TABLE3\n%s", cs.state.pretty_print(ignore_dirs=True))
    assert(len(cs.state) == 3)


