# pylint: disable=missing-docstring,protected-access,too-many-locals

import logging
import time
from io import BytesIO
from typing import List
from itertools import permutations
from platform import system

from unittest.mock import patch, MagicMock

import pytest

from cloudsync.tests.fixtures import WaitFor, RunUntilHelper
from cloudsync import SyncManager, SyncState, CloudFileExistsError, CloudFileNotFoundError, CloudFileNameError,\
        LOCAL, REMOTE, FILE, DIRECTORY, Event, CloudTemporaryError, Notification,\
        NotificationManager, NotificationType
from cloudsync.runnable import _BackoffError
from cloudsync.provider import Provider
from cloudsync.types import OInfo, IgnoreReason
from cloudsync.sync.state import TRASHED, MISSING, SideState

log = logging.getLogger(__name__)

TIMEOUT = 4


class SyncMgrMixin(SyncManager, RunUntilHelper):
    def __init__(self, state, prov, trans, resolv, **kw):
        self.notifications: List[Notification] = []
        def handler(evt):
            self.notifications.append(evt)
        self.nmgr = NotificationManager(handler)
        super().__init__(state, prov, trans, resolv, notification_manager=self.nmgr, **kw)

    def process_notifications(self):
        self.nmgr.notify(None)
        self.nmgr.run()

    def process_events(self, side=None):
        for i in (LOCAL, REMOTE):
            prov = self.providers[i]
            if side is None or side == i:
                for e in prov.events():
                    self.state.update(i, e.otype, path=e.path, oid=e.oid, hash=e.hash, prior_oid=e.prior_oid, exists=e.exists)


def make_sync(_request, providers, shuffle):
    state = SyncState(providers, shuffle=shuffle)

    def translate(to, path):
        if to == LOCAL:
            return "/local" + path.replace("/remote", "")

        if to == REMOTE:
            return "/remote" + path.replace("/local", "")

        raise ValueError("bad path: %s" % path)

    def resolve(_f1, _f2):
        return None

    # two providers and a translation function that converts paths in one to paths in the other
    sync = SyncMgrMixin(state, providers, translate, resolve)

    yield sync

    sync.state.assert_index_is_correct()

    sync.done()


@pytest.fixture(name="sync")
def fixture_sync(request, mock_provider_tuple):
    yield from make_sync(request, mock_provider_tuple, shuffle=True)


@pytest.fixture(name="sync_ordered")
def fixture_sync_ordered(request, mock_provider_tuple):
    yield from make_sync(request, mock_provider_tuple, shuffle=False)


@pytest.fixture(name="sync_sh", params=[0, 1], ids=["sh0", "sh1"])
def fixture_sync_sh(request, mock_provider_tuple):
    yield from make_sync(request, mock_provider_tuple, shuffle=request.param)


@pytest.fixture(name="sync_ci")
def fixture_sync_ci(request, mock_provider_tuple_ci):
    yield from make_sync(request, mock_provider_tuple_ci, shuffle=True)


def setup_remote_local(sync, *names, content=b'hello'):
    local, remote = sync.providers

    remote_parent = "/remote"
    local_parent = "/local"

    local.mkdir(local_parent)
    remote.mkdir(remote_parent)

    found = []
    if type(content) is bytes:
        content = [content]*len(names)

    paths = []
    for i, name in enumerate(names):
        is_dir = name.endswith("/")
        name = name.strip("/")

        remote_path1 = "/remote/" + name
        local_path1 = "/local/" + name
        if "/" in name:
            local_dir1 = "/local/" + remote.dirname(name)
            local.mkdir(local_dir1)
        if is_dir:
            local.mkdir(local_path1)
        else:
            local.create(local_path1, BytesIO(content[i]))
        found.append((REMOTE, remote_path1))
        paths.append((local_path1, remote_path1))

    sync.process_events()
    sync.run_until_found(*found)
    sync.run_until_clean(timeout=1)

    ret = []
    for path in paths:
        ret.append((local.info_path(path[0]), remote.info_path(path[1])))
    return ret


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
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.create_event(LOCAL, FILE, oid=linfo.oid, exists=True)

    assert sync.state.entry_count() == 1
    assert sync.state.changeset_len == 1
    assert sync.change_count(REMOTE) == 0
    assert sync.change_count(LOCAL) == 1

    rinfo = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

    # inserts info about some cloud path
    sync.create_event(REMOTE, FILE, oid=rinfo.oid,
                      path=remote_path2, hash=rinfo.hash)

    def done():
        has_info: List[OInfo] = [None] * 4
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
    assert info
    assert info.hash == sync.providers[LOCAL].hash_oid(info.oid)
    assert info.oid
    log.debug("all state %s", sync.state.get_all())

    sync.state.assert_index_is_correct()


def test_sync_conflict_rename_path(sync):
    base = "/some@.o dd/cr azy.path"
    join = sync.providers[LOCAL].join

    sync.providers[LOCAL].mkdirs(base)
    path = join(base, "to()a.doc.zip")
    sync.providers[LOCAL].create(path, BytesIO(b"hello"))
    oid, new, cpath = sync.conflict_rename(LOCAL, path)
    assert cpath == join(base, "to()a.conflicted.doc.zip")
    sync.providers[LOCAL].create(path, BytesIO(b"hello"))
    oid, new, cpath = sync.conflict_rename(LOCAL, path)
    assert cpath == join(base, "to()a.conflicted2.doc.zip")


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
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    new_oid = sync.providers[LOCAL].rename(linfo.oid, local_path2)

    sync.create_event(LOCAL, FILE, path=local_path2,
                      oid=new_oid, hash=linfo.hash, prior_oid=linfo.oid)

    sync.run_until_found((REMOTE, remote_path2))

    assert sync.providers[REMOTE].info_path("/remote/stuff") is None
    sync.state.assert_index_is_correct()


def test_sync_hash(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = "/local/stuff1"
    remote_path1 = "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    linfo = sync.providers[LOCAL].upload(linfo.oid, BytesIO(b"hello2"))

    sync.create_event(LOCAL, FILE, linfo.oid, hash=linfo.hash)

    sync.run_until_found(WaitFor(REMOTE, remote_path1, hash=linfo.hash))

    info = sync.providers[REMOTE].info_path(remote_path1)

    check = BytesIO()
    sync.providers[REMOTE].download(info.oid, check)

    assert check.getvalue() == b"hello2"
    sync.state.assert_index_is_correct()


def test_sync_rm(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = Provider.join(local_parent, "stuff1")  # "/local/stuff1"
    remote_path1 = Provider.join(remote_parent, "stuff1")  # "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(b"hello"))

    # inserts info about some local path
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    sync.providers[LOCAL].delete(linfo.oid)
    sync.create_event(LOCAL, FILE, linfo.oid, exists=False)

    sync.run_until_found(WaitFor(REMOTE, remote_path1, exists=False))

    assert sync.providers[REMOTE].info_path(remote_path1) is None

    sync.state.assert_index_is_correct()


def test_sync_mkdir(sync):
    local_dir1 = "/local"
    local_path1 = "/local/stuff"
    remote_dir1 = "/remote"
    remote_path1 = "/remote/stuff"

    local_dir_oid1 = sync.providers[LOCAL].mkdir(local_dir1)
    local_path_oid1 = sync.providers[LOCAL].mkdir(local_path1)

    # inserts info about some local path
    sync.create_event(LOCAL, DIRECTORY, path=local_dir1,
                      oid=local_dir_oid1)
    sync.create_event(LOCAL, DIRECTORY, path=local_path1,
                      oid=local_path_oid1)

    sync.run_until_found((REMOTE, remote_dir1))
    sync.run_until_found((REMOTE, remote_path1))

    log.debug("BEFORE DELETE\n %s", sync.state.pretty_print())

    sync.providers[LOCAL].delete(local_path_oid1)
    sync.create_event(LOCAL, FILE, local_path_oid1, exists=False)

    log.debug("AFTER DELETE\n %s", sync.state.pretty_print())

    log.debug("wait for delete")
    sync.run_until_found(WaitFor(REMOTE, remote_path1, exists=False))

    assert sync.providers[REMOTE].info_path(remote_path1) is None
    sync.state.assert_index_is_correct()


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
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)
    sync.create_event(REMOTE, FILE, path=remote_path1,
                      oid=rinfo.oid, hash=rinfo.hash)

    # one of them is a conflict
    sync.run(until=lambda:
             sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted")
             or
             sync.providers[LOCAL].exists_path("/local/stuff1.conflicted")
             )

    sync.run_until_found(
        (REMOTE, "/remote/stuff1"),
        (LOCAL, "/local/stuff1")
    )

    sync.providers[LOCAL]._log_debug_state("LOCAL")              # type: ignore
    sync.providers[REMOTE]._log_debug_state("REMOTE")            # type: ignore

    b1 = BytesIO()
    b2 = BytesIO()
    if sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted"):
        sync.providers[REMOTE].download_path("/remote/stuff1.conflicted", b1)
        sync.providers[REMOTE].download_path("/remote/stuff1", b2)
    else:
        sync.providers[LOCAL].download_path("/local/stuff1.conflicted", b2)
        sync.providers[LOCAL].download_path("/local/stuff1", b1)

    # both files are intact
    assert b1.getvalue() != b2.getvalue()
    assert b1.getvalue() in (b"hello", b"goodbye")
    assert b2.getvalue() in (b"hello", b"goodbye")
    sync.state.assert_index_is_correct()


MERGE = 2


@pytest.mark.parametrize("keep", [True, False])
@pytest.mark.parametrize("side", [LOCAL, REMOTE, MERGE])
def test_sync_conflict_resolve(sync, side, keep):
    data = (b"hello", b"goodbye", b"merge")

    def resolver(f1, f2):
        if side == MERGE:
            return (BytesIO(data[MERGE]), keep)

        if f1.side == side:
            return (f1, keep)

        return (f2, keep)

    sync.set_resolver(resolver)

    remote_parent = "/remote"
    local_parent = "/local"
    local_path1 = Provider.join(local_parent, "stuff1")  # "/local/stuff1"
    remote_path1 = Provider.join(remote_parent, "stuff1")  # "/remote/stuff1"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)

    linfo = sync.providers[LOCAL].create(local_path1, BytesIO(data[LOCAL]))
    rinfo = sync.providers[REMOTE].create(remote_path1, BytesIO(data[REMOTE]))

    # inserts info about some local path
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)
    sync.create_event(REMOTE, FILE, path=remote_path1,
                      oid=rinfo.oid, hash=rinfo.hash)

    # ensure events are flushed a couple times
    sync.run_until_found((REMOTE, "/remote/stuff1"))

    sync.run_until_clean(timeout=1)

    sync.providers[LOCAL]._log_debug_state("LOCAL")      # type: ignore
    sync.providers[REMOTE]._log_debug_state("REMOTE")    # type: ignore

    b1 = BytesIO()
    b2 = BytesIO()
    sync.providers[REMOTE].download_path("/remote/stuff1", b2)
    sync.providers[LOCAL].download_path("/local/stuff1", b1)

    # both files are intact
    assert b1.getvalue() == data[side]
    assert b2.getvalue() == data[side]

    if not keep:
        assert not sync.providers[LOCAL].exists_path("/local/stuff1.conflicted")
        assert not sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted")
    else:
        assert sync.providers[LOCAL].exists_path("/local/stuff1.conflicted") or sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted")

    assert not sync.providers[LOCAL].exists_path("/local/stuff1.conflicted.conflicted")
    assert not sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted.conflicted")
    assert not sync.providers[LOCAL].exists_path("/local/stuff1.conflicted2")
    assert not sync.providers[REMOTE].exists_path("/remote/stuff1.conflicted2")

    sync.state.assert_index_is_correct()


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
    sync.create_event(LOCAL, FILE, path=local_path1, oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    rinfo = sync.providers[REMOTE].info_path(remote_path1)

    assert len(sync.state.get_all()) == 1

    ent = sync.state.get_all().pop()

    sync.providers[REMOTE]._log_debug_state("BEFORE")        # type: ignore

    new_oid_l = sync.providers[LOCAL].rename(linfo.oid, local_path2)
    new_oid_r = sync.providers[REMOTE].rename(rinfo.oid, remote_path2)

    sync.providers[REMOTE]._log_debug_state("AFTER")         # type: ignore

    sync.create_event(LOCAL, FILE, path=local_path2, oid=new_oid_l, hash=linfo.hash, prior_oid=linfo.oid)

    assert len(sync.state.get_all()) == 1
    assert ent[REMOTE].oid == new_oid_r

    sync.create_event(REMOTE, FILE, path=remote_path2, oid=new_oid_r, hash=rinfo.hash, prior_oid=rinfo.oid)

    assert len(sync.state.get_all()) == 1

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    # defer to the one renamed "first", which in this case is local
    sync.run_until_found((LOCAL, local_path2))
    sync.run_until_found((REMOTE, "/remote/stuff-l"))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    assert not sync.providers[REMOTE].exists_path(remote_path2)
    assert not sync.providers[LOCAL].exists_path(local_path1)
    assert not sync.providers[REMOTE].exists_path(remote_path1)
    assert not sync.providers[LOCAL].exists_path("/local/stuff-r")
    sync.state.assert_index_is_correct()


def test_sync_cycle(sync: SyncMgrMixin):
    l_parent = "/local"
    r_parent = "/remote"
    lp1, lp2, lp3 = "/local/a", "/local/b", "/local/c",
    rp1, rp2, rp3 = "/remote/a", "/remote/b", "/remote/c",
    templ = "/local/d"

    l_parent_oid = sync.providers[LOCAL].mkdir(l_parent)
    r_parent_oid = sync.providers[REMOTE].mkdir(r_parent)

    linfo1 = sync.providers[LOCAL].create(lp1, BytesIO(b"hello1"))
    sync.create_event(LOCAL, FILE, path=lp1, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, rp1), timeout=1)
    rinfo1 = sync.providers[REMOTE].info_path(rp1)

    linfo2 = sync.providers[LOCAL].create(lp2, BytesIO(b"hello2"))
    sync.create_event(LOCAL, FILE, path=lp2, oid=linfo2.oid, hash=linfo2.hash)
    sync.run_until_found((REMOTE, rp2))
    rinfo2 = sync.providers[REMOTE].info_path(rp2)

    linfo3 = sync.providers[LOCAL].create(lp3, BytesIO(b"hello3"))
    sync.create_event(LOCAL, FILE, path=lp3, oid=linfo3.oid, hash=linfo3.hash)
    sync.run_until_found((REMOTE, rp3))
    rinfo3 = sync.providers[REMOTE].info_path(rp3)

    sync.providers[REMOTE]._log_debug_state("BEFORE")                # type: ignore
    tmp1oid = sync.providers[LOCAL].rename(linfo1.oid, templ)
    lp1oid = sync.providers[LOCAL].rename(linfo3.oid, lp1)
    lp3oid = sync.providers[LOCAL].rename(linfo2.oid, lp3)
    lp2oid = sync.providers[LOCAL].rename(tmp1oid, lp2)

    # a->temp, c->a, b->c, temp->b

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.create_event(LOCAL, FILE, path=templ, oid=tmp1oid, hash=linfo1.hash, prior_oid=linfo1.oid)
    log.debug("TABLE 1:\n%s", sync.state.pretty_print())
    sync.create_event(LOCAL, FILE, path=lp1, oid=lp1oid, hash=linfo3.hash, prior_oid=linfo3.oid)
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())
    sync.create_event(LOCAL, FILE, path=lp3, oid=lp3oid, hash=linfo2.hash, prior_oid=linfo2.oid)
    log.debug("TABLE 3:\n%s", sync.state.pretty_print())
    sync.create_event(LOCAL, FILE, path=lp2, oid=lp2oid, hash=linfo1.hash, prior_oid=tmp1oid)
    log.debug("TABLE 4:\n%s", sync.state.pretty_print())
    assert len(sync.state.get_all()) == 3
    sync.providers[REMOTE]._log_debug_state("MIDDLE")                # type: ignore

    sync.run_until_clean(timeout=1)
    sync.providers[REMOTE]._log_debug_state("AFTER")                 # type: ignore

    i1 = sync.providers[REMOTE].info_path(rp1)
    i2 = sync.providers[REMOTE].info_path(rp2)
    i3 = sync.providers[REMOTE].info_path(rp3)
    ldir = sorted([x.name for x in sync.providers[LOCAL].listdir(l_parent_oid)])
    rdir = sorted([x.name for x in sync.providers[REMOTE].listdir(r_parent_oid)])

    log.debug("ldir=%s", ldir)
    log.debug("rdir=%s", rdir)
    log.debug("path %s has info %s", rp1, i1)
    log.debug("path %s has info %s", rp2, i2)
    log.debug("path %s has info %s", rp3, i3)

    assert i1
    assert i2
    assert i3

    assert rinfo1
    assert rinfo2
    assert rinfo3

    assert i1.hash == rinfo3.hash
    assert i2.hash == rinfo1.hash
    assert i3.hash == rinfo2.hash


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
    sync.create_event(LOCAL, FILE, path=local_path1,
                      oid=linfo1.oid, hash=linfo1.hash)

    sync.create_event(REMOTE, FILE, path=remote_path2,
                      oid=rinfo2.oid, hash=rinfo2.hash)

    sync.run_until_found((REMOTE, remote_path1), (LOCAL, local_path2))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    new_oid1 = sync.providers[LOCAL].rename(linfo1.oid, local_path3)
    prior_oid = sync.providers[LOCAL].oid_is_path and linfo1.oid
    sync.create_event(LOCAL, FILE, path=local_path3, oid=new_oid1, prior_oid=prior_oid)

    new_oid2 = sync.providers[REMOTE].rename(rinfo2.oid, remote_path3)
    prior_oid = sync.providers[REMOTE].oid_is_path and rinfo2.oid
    sync.create_event(REMOTE, FILE, path=remote_path3, oid=new_oid2, prior_oid=prior_oid)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    ok = lambda: (
        sync.providers[REMOTE].exists_path("/remote/stuff.conflicted")
        or
        sync.providers[LOCAL].exists_path("/local/stuff.conflicted")
    )
    sync.run(until=ok, timeout=3)

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    assert ok()


def test_event_order_del_create(sync):
    local_parent, remote_parent = ("/local", "/remote")
    local, remote = sync.providers
    local.mkdir(local_parent)
    remote.mkdir(remote_parent)

    remote_path1 = Provider.join(remote_parent, "stuff1")
    local_path1 = sync.translate(LOCAL, remote_path1).replace("\\", "/")
    rinfo1 = sync.providers[REMOTE].create(remote_path1, BytesIO(b"hello"))

    # insert the delete event before the create event, file exists, confirm it exists locally after syncing
    sync.create_event(REMOTE, FILE, path=remote_path1, oid=rinfo1.oid, hash=rinfo1.hash, exists=False)
    sync.run_until_clean(timeout=1)
    sync.create_event(REMOTE, FILE, oid=rinfo1.oid, exists=True)
    sync.run_until_clean(timeout=1)

    assert sync.providers[LOCAL].info_path(local_path1) is not None

    remote_path2 = "/remote/stuff2"
    local_path2 = "/local/stuff2"
    rinfo2 = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello"))
    sync.providers[REMOTE].delete(rinfo2.oid)

    # insert the delete event before the create event, file trashed, confirm it doesn't exist locally after syncing
    sync.create_event(REMOTE, FILE, path=remote_path2, oid=rinfo2.oid, hash=rinfo2.hash, exists=False)
    sync.run_until_clean(timeout=1)
    sync.create_event(REMOTE, FILE, oid=rinfo2.oid, exists=True)
    sync.run_until_clean(timeout=1)

    assert sync.providers[LOCAL].info_path(local_path2) is None


@pytest.mark.manual
@pytest.mark.parametrize("order", list(permutations(range(6), 6)))
def test_event_order_permute(order, sync):  # pragma: no cover
    local_parent, remote_parent = ("/local", "/remote")
    local, remote = sync.providers
    local.mkdir(local_parent)
    remote.mkdir(remote_parent)

    def target_hash(suffix):
        return local.hash_data(BytesIO(b"hello" + bytes(str(suffix), "utf8")))

    fn_suffix = "".join([str(i) for i in order])
    log.debug("test ordering = %s", fn_suffix)
    local_path_a = "/local/stuffa" + fn_suffix
    local_path_b = "/local/stuffb" + fn_suffix
    local_path_c = "/local/stuffc" + fn_suffix
    remote_path_a = "/remote/stuffa" + fn_suffix
    remote_path_b = "/remote/stuffb" + fn_suffix
    remote_path_c = "/remote/stuffc" + fn_suffix

    rinfo_1 = remote.create(remote_path_b, BytesIO(b"hello1"))
    remote.delete(rinfo_1.oid)
    rinfo_2 = remote.create(remote_path_a, BytesIO(b"hello2"))
    remote.rename(rinfo_2.oid, remote_path_b)
    remote.rename(rinfo_2.oid, remote_path_c)
    rinfo_3 = remote.create(remote_path_b, BytesIO(b"hello3"))

    # Event(otype=, oid=, path=, hash=, exists=, mtime=, prior_oid=, new_cursor=)
    events = [
        Event(otype=FILE, oid=rinfo_1.oid, path=remote_path_a, hash=rinfo_1.hash, exists=True, mtime=1),  # create b
        Event(otype=FILE, oid=rinfo_1.oid, path=remote_path_a, hash=rinfo_1.hash, exists=False, mtime=2),  # trash b

        Event(otype=FILE, oid=rinfo_2.oid, path=remote_path_a, hash=rinfo_2.hash, exists=True, mtime=3),  # create a
        Event(otype=FILE, oid=rinfo_2.oid, path=remote_path_b, hash=rinfo_2.hash, exists=True, mtime=4),  # rename to b
        Event(otype=FILE, oid=rinfo_2.oid, path=remote_path_c, hash=rinfo_2.hash, exists=True, mtime=5),  # rename to c

        Event(otype=FILE, oid=rinfo_3.oid, path=remote_path_b, hash=rinfo_3.hash, exists=True, mtime=6),  # create b
    ]
    for event_no in order:
        event = events[event_no]
        log.info("Processing event %s:%s", event.mtime, event)
        sync.insert_event(REMOTE, event)
        sync.run_until_clean(timeout=1)

    linfo_a = local.info_path(local_path_a)
    linfo_b = local.info_path(local_path_b)
    linfo_c = local.info_path(local_path_c)
    assert linfo_a is None
    assert linfo_b.hash == target_hash("3")
    assert linfo_c.hash == target_hash("2")


def test_create_then_move(sync):  # TODO: combine with the reverse test
    remote_parent = "/remote"
    local_parent = "/local"
    local_folder = "/local/folder"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"
    local_file2 = "/local/folder/file"
    remote_file2 = "/remote/folder/file"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    linfo1 = sync.providers[LOCAL].create(local_file1, BytesIO(b"hello"))
    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, remote_file1))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    folder_oid = sync.providers[LOCAL].mkdir(local_folder)
    sync.create_event(LOCAL, DIRECTORY, path=local_folder, oid=folder_oid, hash=None)

    new_oid = sync.providers[LOCAL].rename(linfo1.oid, local_file2)
    sync.create_event(LOCAL, FILE, path=local_file2, oid=new_oid, hash=linfo1.hash, prior_oid=linfo1.oid)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())
    sync.run_until_found((REMOTE, remote_file2), timeout=2)
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())


def test_create_then_move_reverse(sync):  # TODO: see if this can be combined with the reverse test
    remote_parent = "/remote"
    local_parent = "/local"
    remote_folder = "/remote/folder"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"
    local_file2 = "/local/folder/file"
    remote_file2 = "/remote/folder/file"

    oid = sync.providers[LOCAL].mkdir(local_parent)
    oid = sync.providers[REMOTE].mkdir(remote_parent)
    rinfo1 = sync.providers[REMOTE].create(remote_file1, BytesIO(b"hello"))
    sync.create_event(REMOTE, FILE, path=remote_file1, oid=rinfo1.oid, hash=rinfo1.hash)
    sync.run_until_found((LOCAL, local_file1))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    folder_oid = sync.providers[REMOTE].mkdir(remote_folder)
    sync.create_event(REMOTE, DIRECTORY, path=remote_folder, oid=folder_oid, hash=None)

    sync.providers[REMOTE].rename(rinfo1.oid, remote_file2)
    sync.create_event(REMOTE, FILE, path=remote_file2, oid=rinfo1.oid, hash=rinfo1.hash)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())
    sync.run_until_found((LOCAL, local_file2), timeout=2)
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())


def _test_rename_folder_with_kids(sync, source, dest):
    parent = ["/local", "/remote"]
    folder1 = ["/local/folder1", "/remote/folder1"]
    file1 = ["/local/folder1/file", "/remote/folder1/file"]
    folder2 = ["/local/folder2", "/remote/folder2"]
    file2 = ["/local/folder2/file", "/remote/folder2/file"]

    for loc in (source, dest):
        sync.providers[loc].mkdir(parent[loc])
    folder_oid = sync.providers[source].mkdir(folder1[source])
    sync.create_event(source, DIRECTORY, path=folder1[source], oid=folder_oid, hash=None)

    file_info: OInfo = sync.providers[source].create(file1[source], BytesIO(b"hello"))
    sync.create_event(source, FILE, path=file1[source], oid=file_info.oid, hash=None)

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.run_until_found((dest, folder1[dest]))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    new_oid = sync.providers[source].rename(folder_oid, folder2[source])
    sync.create_event(source, DIRECTORY, path=folder2[source], oid=new_oid, hash=None, prior_oid=folder_oid)

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())
    sync.run_until_found(
        (source, file2[source]),
        (dest, file2[dest])
    )
    log.debug("TABLE 3:\n%s", sync.state.pretty_print())


@pytest.mark.parametrize("ordering", [(LOCAL, REMOTE), (REMOTE, LOCAL)])
def test_rename_folder_with_kids(sync_sh, ordering):
    _test_rename_folder_with_kids(sync_sh, *ordering)


def test_aging(sync):
    local_parent = "/local"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"
    local_file2 = "/local/file2"
    remote_file2 = "/remote/file2"

    sync.providers[LOCAL].mkdir(local_parent)
    linfo1 = sync.providers[LOCAL].create(local_file1, BytesIO(b"hello"))

    # aging slows things down
    sync.aging = 0.2
    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)
    sync.do()
    sync.do()
    sync.do()
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    assert not sync.providers[REMOTE].info_path(local_file1)

    sync.run_until_found((REMOTE, remote_file1), timeout=2)

    assert sync.providers[REMOTE].info_path(remote_file1)

    sync.aging = 0
    linfo2 = sync.providers[LOCAL].create(local_file2, BytesIO(b"hello"))
    sync.create_event(LOCAL, FILE, path=local_file2, oid=linfo2.oid, hash=linfo2.hash)
    sync.do()
    sync.do()
    sync.do()
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    assert sync.providers[REMOTE].info_path(remote_file2)
    # but withotu it, things are fast


def test_remove_folder_with_kids(sync_sh):
    sync = sync_sh
    parent = ["/local", "/remote"]
    folder1 = ["/local/folder1", "/remote/folder1"]
    file1 = ["/local/folder1/file", "/remote/folder1/file"]

    for loc in (LOCAL, REMOTE):
        sync.providers[loc].mkdir(parent[loc])
    folder_oid = sync.providers[LOCAL].mkdir(folder1[LOCAL])
    sync.create_event(LOCAL, DIRECTORY, path=folder1[LOCAL], oid=folder_oid, hash=None)

    file_info: OInfo = sync.providers[LOCAL].create(file1[LOCAL], BytesIO(b"hello"))
    sync.create_event(LOCAL, FILE, path=file1[LOCAL], oid=file_info.oid, hash=None)

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.run_until_found((REMOTE, file1[REMOTE]))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    sync.providers[LOCAL].delete(file_info.oid)
    sync.providers[LOCAL].delete(folder_oid)

    sync.create_event(LOCAL, DIRECTORY, oid=file_info.oid, exists=False)
    sync.create_event(LOCAL, DIRECTORY, oid=folder_oid, exists=False)

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    sync.run_until_found(WaitFor(REMOTE, file1[REMOTE], exists=False), WaitFor(REMOTE, folder1[REMOTE], exists=False))


def test_dir_rm(sync):
    remote_parent = "/remote"
    local_parent = "/local"
    local_dir = Provider.join(local_parent, "dir")
    remote_dir = Provider.join(remote_parent, "dir")
    local_file = Provider.join(local_dir, "file")
    remote_file = Provider.join(remote_dir, "file")

    lparent = sync.providers[LOCAL].mkdir(local_parent)
    rparent = sync.providers[REMOTE].mkdir(remote_parent)
    ldir = sync.providers[LOCAL].mkdir(local_dir)
    rdir = sync.providers[REMOTE].mkdir(remote_dir)
    lfile = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    sync.create_event(LOCAL, DIRECTORY, path=local_dir, oid=ldir)
    sync.create_event(LOCAL, FILE, path=local_file, oid=lfile.oid, hash=lfile.hash)

    sync.run_until_found((REMOTE, remote_file), (REMOTE, remote_dir))

    rfile = sync.providers[REMOTE].info_path(remote_file)
    sync.providers[REMOTE].delete(rfile.oid)
    sync.providers[REMOTE].delete(rdir)

    # Directory delete - should punt because of children
    # aging needs to be at most negative punt_secs or this test will be flaky, because the parent folder
    # will de-age when it punts by that amount, and then the folder won't have aged enough to get deleted on time
    sync.aging = 0 - max(sync.state._punt_secs)
    sync.create_event(REMOTE, DIRECTORY, path=remote_dir, oid=rdir, exists=False)
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(ldir))) == 1

    sync.create_event(REMOTE, FILE, path=remote_file, oid=rfile.oid, exists=False)
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(ldir))) == 0

    # Now it should successfully rmdir
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(lparent))) == 0

    sync.state.assert_index_is_correct()


def test_no_change_does_nothing(sync):
    local_parent = "/local"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"

    sync.providers[LOCAL].mkdir(local_parent)
    linfo1 = sync.providers[LOCAL].create(local_file1, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)

    sync.run_until_clean(timeout=1)

    rinfo1 = sync.providers[REMOTE].info_path(remote_file1)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    sync.state.lookup_oid(LOCAL, linfo1.oid)[LOCAL].changed = 1
    sync.state.lookup_oid(REMOTE, rinfo1.oid)[REMOTE].changed = 1

    assert sync.state.changeset_len
    assert not sync.state.lookup_oid(LOCAL, linfo1.oid)[LOCAL].needs_sync()
    assert not sync.state.lookup_oid(REMOTE, rinfo1.oid)[REMOTE].needs_sync()

    sync.run_until_clean(timeout=1)

    assert sync.state.lookup_oid(LOCAL, linfo1.oid)[LOCAL].sync_path
    assert sync.state.lookup_oid(REMOTE, rinfo1.oid)[REMOTE].sync_path
    assert sync.state.lookup_oid(LOCAL, linfo1.oid)[LOCAL].sync_hash
    assert sync.state.lookup_oid(REMOTE, rinfo1.oid)[REMOTE].sync_hash


def test_file_name_error(sync):
    local_parent = "/local"
    local_file1 = "/local/file1"
    local_file2 = "/local/file2"
    local_file3 = "/local/file3"
    remote_file1 = "/remote/file1"
    remote_file2 = "/remote/file2"
    remote_file3 = "/remote/file3"

    sync.providers[LOCAL].mkdir(local_parent)
    linfo1 = sync.providers[LOCAL].create(local_file1, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)

    called = False

    def _called(*args):
        nonlocal called
        called = True
        raise CloudFileNameError("file name error")

    with patch.object(sync.providers[REMOTE], "create", new=_called):
        sync.run(until=lambda: called, timeout=1)

    sync.do()

    assert not sync.providers[REMOTE].info_path(remote_file1)
    assert sync.state.lookup_oid(LOCAL, linfo1.oid).ignored == IgnoreReason.IRRELEVANT

    linfo2 = sync.providers[LOCAL].create(local_file2, BytesIO(b"hello"))
    sync.create_event(LOCAL, FILE, path=local_file2, oid=linfo2.oid, hash=linfo2.hash)
    sync.run(until=lambda: sync.providers[REMOTE].exists_path(remote_file2), timeout=1)
    assert sync.providers[REMOTE].info_path(remote_file2)

    new_oid = sync.providers[LOCAL].rename(linfo2.oid, local_file3)
    sync.create_event(LOCAL, FILE, path=local_file3, oid=new_oid, hash=linfo2.hash, prior_oid=linfo2.oid)

    called = False
    with patch.object(sync.providers[REMOTE], "rename", new=_called):
        sync.run(until=lambda: called, timeout=1)

    sync.do()

    assert not sync.providers[REMOTE].info_path(remote_file3)
    assert sync.state.lookup_oid(LOCAL, new_oid).ignored == IgnoreReason.IRRELEVANT

def test_modif_rename(sync):
    local_parent = "/local"
    local_file1 = "/local/file"
    local_file2 = "/local/file2"
    remote_file1 = "/remote/file"
    remote_file2 = "/remote/file2"

    sync.providers[LOCAL].mkdir(local_parent)
    linfo1 = sync.providers[LOCAL].create(local_file1, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, remote_file1))

    linfo2 = sync.providers[LOCAL].upload(linfo1.oid, BytesIO(b"hello2"))
    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo2.hash)
    new_loid = sync.providers[LOCAL].rename(linfo1.oid, local_file2)

    log.debug("CHANGE LF1 NO REN EVENT")
    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.run(until=lambda: not sync.busy, timeout=1)

    if sync.providers[LOCAL].oid_is_path:
        # other providers can figure out the rename happend
        assert sync.providers[REMOTE].info_path(remote_file1) is not None

    log.debug("REN EVENT")
    sync.create_event(LOCAL, FILE, path=local_file2,
                      oid=new_loid, prior_oid=linfo1.oid)

    sync.run_until_found((REMOTE, remote_file2))

    assert sync.providers[REMOTE].info_path(remote_file2)

def test_create_cloud_fnf_error(sync):
    local_parent = "/local"
    local_file = "/local/dir/file"
    local_dir_to_create = "/local/dir"
    remote_file = "/remote/dir/file"
    remote_dir_to_create = "/remote/dir/"

    sync.providers[LOCAL].mkdir(local_parent)
    # Local provider is aware of dir_to_create but doesn't send event to cloudsync
    # This will cause the remote create to throw a CloudFileNotFoundError
    with patch.object(sync.providers[LOCAL], "_register_event"):
        sync.providers[LOCAL].mkdir(local_dir_to_create)
    linfo1 = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, remote_file))

    assert sync.providers[REMOTE].info_path(remote_dir_to_create)

def test_rename_cloud_fnf_error(sync):
    local_parent = "/local"
    local_file = "/local/file"
    local_file_moved = "/local/dir/file"
    local_dir_to_create = "/local/dir"
    remote_file = "/remote/file"
    remote_file_moved = "/remote/dir/file"
    remote_dir_to_create = "/remote/dir/"

    sync.providers[LOCAL].mkdir(local_parent)
    # Local provider is aware of dir_to_create but doesn't send event to cloudsync
    # This will cause the remote rename to throw a CloudFileNotFoundError
    with patch.object(sync.providers[LOCAL], "_register_event"):
        sync.providers[LOCAL].mkdir(local_dir_to_create)
    linfo1 = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, remote_file))

    new_loid = sync.providers[LOCAL].rename(linfo1.oid, local_file_moved)
    sync.create_event(LOCAL, FILE, path=local_file_moved, oid=new_loid, hash=None, prior_oid=linfo1.oid)
    sync.run_until_found((REMOTE, remote_file_moved))

    assert sync.providers[REMOTE].info_path(remote_dir_to_create)

def test_re_mkdir_synced(sync):
    local_parent = "/local"
    local_sub = "/local/sub"
    local_file = "/local/sub/file"
    remote_sub = "/remote/sub"
    remote_file = "/remote/sub/file"

    sync.providers[LOCAL].mkdir(local_parent)
    lsub_oid = sync.providers[LOCAL].mkdir(local_sub)
    lfil = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)

    sync.run_until_found((REMOTE, remote_file))

    rfil = sync.providers[REMOTE].info_path(remote_file)
    sync.providers[REMOTE].upload(rfil.oid, BytesIO(b"hello2"))

    sync.providers[LOCAL].delete(lfil.oid)
    sync.providers[LOCAL].delete(lsub_oid)

    sync.run(until=lambda: not sync.busy)
    sync.create_event(REMOTE, FILE, path=remote_file, oid=rfil.oid, hash=rfil.hash)

    log.info("TABLE 0:\n%s", sync.state.pretty_print())

    sync.run_until_found((LOCAL, local_file))


def test_path_conflict_deleted_remotely(sync):
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/a"
    local_path1 = "/local/a"
    new_remote_path1 = "/remote/b"
    new_remote_path2 = "/remote/c"
    new_local_path1 = "/local/c"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    local_oid = sync.providers[LOCAL].mkdir(local_path1)
    sync.create_event(LOCAL, DIRECTORY, path=local_path1, oid=local_oid)
    sync.run_until_found((REMOTE, remote_path1))
    remote_info = sync.providers[REMOTE].info_path(remote_path1)
    remote_oid = remote_info.oid
    new_local_oid = sync.providers[LOCAL].rename(local_oid, new_local_path1)
    new_remote_oid = sync.providers[REMOTE].rename(remote_oid, new_remote_path1)
    sync.providers[REMOTE].delete(new_remote_oid)
    sync.create_event(LOCAL, DIRECTORY, path=new_local_path1, oid=new_local_oid, prior_oid=local_oid)
    sync.create_event(REMOTE, DIRECTORY, path=new_remote_path1, oid=new_remote_oid, prior_oid=remote_oid, exists=False)
    sync.run_until_clean()  # with the bug, this will loop forever/timeout
    assert not sync.providers[LOCAL].info_oid(new_local_oid)
    assert not sync.providers[REMOTE].info_oid(new_remote_oid)

def test_backoff_cleared_after_delete_synced(sync):
    local_parent = "/local"
    local_sub = "/local/sub"
    local_file = "/local/sub/file"

    # create local folders + file, sync to remote
    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[LOCAL].mkdir(local_sub)
    lfil = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))
    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
    sync.run_until_clean(timeout=1)
    log.info("TABLE 0:\n%s", sync.state.pretty_print())

    # delete local file -- ensure something happened
    with patch.object(sync, "nothing_happened") as nothing_happened:
        sync.providers[LOCAL].delete(lfil.oid)
        sync.create_event(LOCAL, FILE, oid=lfil.oid, exists=TRASHED)
        sync.run_until_clean(timeout=1)
        nothing_happened.assert_not_called()

def test_equivalent_path_and_sync_path_do_nothing(sync):
    local_parent = "/local"
    local_sub = "/local/sub"
    local_file = "/local/sub/file"

    # create local folders + file
    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[LOCAL].mkdir(local_sub)
    lfil = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    # sync local file to remote
    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
    sync.run_until_clean(timeout=1)
    log.info("TABLE 0:\n%s", sync.state.pretty_print())
    sync_entry = sync.state.lookup_oid(LOCAL, lfil.oid)

    with patch.object(sync, "nothing_happened") as nothing_happened:
        sync_entry[LOCAL].sync_path = "/local/sub\\file"
        sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
        sync.run_until_clean(timeout=1)
        nothing_happened.assert_called()

    with patch.object(sync, "nothing_happened") as nothing_happened:
        sync_entry[LOCAL].sync_path = "\\local\\sub/file"
        sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
        sync.run_until_clean(timeout=1)
        nothing_happened.assert_called()


@pytest.mark.skipif(system() == "Linux", reason="flaky on travis CI")
def test_reprioritize_sync_trash_loop(sync):
    # an admittedly contrived scenario that causes sync to loop forever

    local_parent = "/local"
    local_sub = "/local/sub"
    local_file = "/local/sub/file"

    remote_sub = "/remote/sub"
    remote_file = "/remote/sub/file"

    # create local folders + file
    sync.providers[LOCAL].mkdir(local_parent)
    lsub_oid = sync.providers[LOCAL].mkdir(local_sub)
    lfil = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    # sync local file to remote
    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
    sync.run_until_clean(timeout=1)
    log.info("TABLE 0:\n%s", sync.state.pretty_print())

    # delete remotes
    rfil_oid = sync.providers[REMOTE].info_path(remote_file).oid
    sync.providers[REMOTE]._delete(rfil_oid, without_event=True)
    rsub_oid = sync.providers[REMOTE].info_path(remote_sub).oid
    sync.providers[REMOTE]._delete(rsub_oid, without_event=True)

    # /sub/file entry
    sync_entry = sync.state.lookup_oid(LOCAL, lfil.oid)
    sync_entry._priority = 1
    sync_entry[REMOTE].exists = TRASHED
    sync_entry[LOCAL].sync_path = "/local/sub\\file"
    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
    sync_entry[REMOTE].changed = sync_entry[LOCAL].changed + 10

    # /sub entry
    sync_entry = sync.state.lookup_oid(LOCAL, lsub_oid)
    sync_entry._priority = 1
    sync.create_event(REMOTE, DIRECTORY, oid=rsub_oid, exists=TRASHED)

    log.info("TABLE 1:\n%s", sync.state.pretty_print())

    # hash func generates LOCAL event
    def hash_creates_event(self):
        if self.type == self.DIR:
            return None
        sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)
        return self._hash_func(self.contents)

    with patch("cloudsync.tests.fixtures.mock_provider.MockFSObject.hash", new=hash_creates_event):
        sync.run_until_clean(timeout=1) # times out if we get into the rename codepath

    # ensure all entries are discarded
    assert sync.state.entry_count() == 0

    log.info("TABLE 2:\n%s", sync.state.pretty_print())


def test_folder_del_loop(sync):
    local_parent = "/local"
    local_sub = "/local/sub"
    local_file = "/local/sub/file"

    local_sub2 = "/local/sub2"
    local_file2 = "/local/sub2/file"

    remote_sub = "/remote/sub"
    remote_file = "/remote/sub/file"
    remote_sub2 = "/remote/sub2"

    sync.providers[LOCAL].mkdir(local_parent)
    lsub_oid = sync.providers[LOCAL].mkdir(local_sub)
    lfil = sync.providers[LOCAL].create(local_file, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file, oid=lfil.oid, hash=lfil.hash)

    sync.run_until_found((REMOTE, remote_file))

    rfil = sync.providers[REMOTE].info_path(remote_file)
    rsub_oid = sync.providers[REMOTE].info_path(remote_sub).oid
    sync.providers[REMOTE].delete(rfil.oid)
    sync.providers[REMOTE].delete(rsub_oid)
    lsub2_oid = sync.providers[LOCAL].rename(lsub_oid, local_sub2)
    lfil2 = sync.providers[LOCAL].info_path(local_file2)

    log.info("TABLE 0:\n%s", sync.state.pretty_print())

    sync.create_event(REMOTE, FILE, oid=rfil.oid, exists=TRASHED)
    sync.run(until=lambda: not sync.busy, timeout=1)

    sync.create_event(LOCAL, DIRECTORY, oid=lsub2_oid, path=local_sub2, prior_oid=lsub_oid)
    sync.create_event(LOCAL, FILE, oid=lfil2.oid, path=local_file2, prior_oid=lfil.oid)
    sync.create_event(REMOTE, DIRECTORY, oid=rsub_oid, exists=TRASHED)

    log.info("TABLE 1:\n%s", sync.state.pretty_print())

    sync.run(until=lambda: not sync.busy, timeout=1)

    assert not sync.providers[REMOTE].info_path(remote_sub)
    # Because of the order of operations above, we can't assert that the folder doesn't exist
    # Since we delete the remote folder and file, but only present the event for the file, and then sync,
    # when we do finally rename the local folder (and the file implicitly by the folder rename)
    # the sync of the local folder rename may happen before the remote folder delete event gets processed into the
    # state table. If so, then get_latest will update the remote.exists to Trashed, but not marked it changed
    # on the remote side because the event hasn't come in yet. To summarize, we have a changed, renamed folder locally
    # and an unchanged, Trashed file remotely, which looks exactly like a CREATE, so we do that. The event for the delete
    # then comes in, but we don't follow the advice of the event, instead we check if both sides match and they do,
    # so we ignore the event. This leaves the folder existing on both sides
    # instead, we'll simply assert that it exists locally and remotely, or is trashed locally and remotely
    remote_exists = sync.providers[REMOTE].info_path(remote_sub2) is not None
    assert not sync.providers[LOCAL].info_path(local_sub)
    local_exists = sync.providers[LOCAL].info_path(local_sub2) is not None
    if remote_exists:
        assert local_exists
    else:
        assert not local_exists


def test_sync_temporary_error(sync_ordered):
    sync = sync_ordered
    local_parent = "/local"
    remote_parent = "/remote"
    remote_path1 = "/remote/a"
    local_path1 = "/local/a"
    remote_path2 = "/remote/b"
    local_path2 = "/local/b"

    sync.providers[LOCAL].mkdir(local_parent)
    sync.providers[REMOTE].mkdir(remote_parent)
    local_info1 = sync.providers[LOCAL].create(local_path1, BytesIO(b'hello'))
    local_oid1 = local_info1.oid
    sync.create_event(LOCAL, DIRECTORY, path=local_path1, oid=local_oid1)
    sync.run_until_found((REMOTE, remote_path1))
    remote_info1 = sync.providers[REMOTE].info_path(remote_path1)
    remote_oid1 = remote_info1.oid

    sync.providers[REMOTE].delete(remote_oid1)
    sync.create_event(REMOTE, DIRECTORY, path=remote_path1, oid=remote_oid1, exists=False)

    time.sleep(.001)

    local_info2 = sync.providers[LOCAL].create(local_path2, BytesIO(b'world'))
    local_oid2 = local_info2.oid
    sync.create_event(LOCAL, DIRECTORY, path=local_path2, oid=local_oid2)

    with patch.object(sync.providers[LOCAL], "delete", side_effect=CloudTemporaryError):
        sync.run_until_found((REMOTE, remote_path2))  # with the bug, this will loop forever/timeout


@pytest.mark.parametrize("order", [LOCAL, REMOTE], ids=("local", "remote"))
def test_replace_rename(sync, order):
    (local, remote) = sync.providers

    (
        (la, ra),
        (lb, rb),
    ) = setup_remote_local(sync, "a", "b", content=(b'a', b'b'))

    log.info("TABLE 0\n%s", sync.state.pretty_print())

    local.upload(la.oid, BytesIO(b'tmp'))
    local._delete(la.oid, without_event=True)
    local.rename(lb.oid, la.path)

    sync.process_events(order)

    log.info("TABLE 1\n%s", sync.state.pretty_print())

    sync.run(until=lambda: not sync.busy, timeout=3)

    log.info("TABLE 2\n%s", sync.state.pretty_print())

    sync.process_events(1-order)

    sync.run(until=lambda: not sync.busy, timeout=3)

    log.info("TABLE 3\n%s", sync.state.pretty_print())

    log.info("%s->%s", ra.path + ".conflicted", remote.info_path(ra.path + ".conflicted"))
    log.info("%s", list(remote.walk("/remote")))

    assert not local.info_path(la.path + ".conflicted")
    assert not local.info_path(lb.path + ".conflicted")
    assert not remote.info_path(ra.path + ".conflicted")
    assert not remote.info_path(rb.path + ".conflicted")

    bio = BytesIO()
    remote.download_path(ra.path, bio)
    assert bio.getvalue() == b'b'


def test_rename_same_name(sync_ci):
    sync = sync_ci
    (local, remote) = sync.providers

    (
        (ld, rd),
        (la, ra),
        (lb, rb),
    ) = setup_remote_local(sync, "d/", "d/a", "d/b", content=(None, b'a', b'b'))

    # this is case insensitive
    assert remote.exists_path("/remote/d")
    assert remote.exists_path("/remote/D")

    ra.oid = remote.rename(ra.oid, "/remote/D/a")

    assert remote.exists_path("/remote/D/a")
    assert remote.exists_path("/remote/d/a")

    sync.create_event(REMOTE, FILE, path="/remote/D/a", oid=ra.oid, hash=ra.hash)

    log.info("TABLE 0\n%s", sync.state.pretty_print())

    log.info("remote %s", list(remote.listdir_path("/remote/d")))

    with patch.object(local, "rename") as m:
        sync.run(until=lambda: not sync.busy, timeout=3)
        assert not m.called

    log.info("TABLE 2\n%s", sync.state.pretty_print())


def test_dir_removal_missing_child(sync):
    (local, remote) = sync.providers

    (
        (lf, rf),
    ) = setup_remote_local(sync, "f/")

    # Missing event for remote create, should sync down when we try to delete its parent
    ra = remote.create("/remote/f/a", BytesIO(b"hello"))
    local.delete(lf.oid)
    sync.create_event(LOCAL, DIRECTORY, path="/local/f", oid=lf.oid, exists=False)

    log.info("TABLE 0\n%s", sync.state.pretty_print())

    sync.run(until=lambda: local.info_path("/local/f/a"), timeout=2)

    log.info("TABLE 1\n%s", sync.state.pretty_print())

    assert local.info_path("/local/f/a")


def test_missing_not_finished(sync):
    (local, remote) = sync.providers
    (
        (ld, rd),
        (la, ra),
    ) = setup_remote_local(sync, "d/", "d/a", content=(b'', b'a'))

    log.info("TABLE 0\n%s", sync.state.pretty_print())

    local._delete(la.oid, without_event=True)
    local.delete(ld.oid)

    sync.create_event(LOCAL, FILE, path="/local/d/a", oid=la.oid, hash=la.hash, exists=True)
    sync.create_event(LOCAL, FILE, path="/local/d", oid=ld.oid, hash=ld.hash, exists=False)
    log.info("TABLE 1\n%s", sync.state.pretty_print())

    local_expected = MISSING if local.oid_is_path else TRASHED
    sync.run(until=lambda: sync.state.lookup_oid(LOCAL, la.oid)[LOCAL].exists == local_expected, timeout=1)

    assert sync.state.lookup_oid(LOCAL, la.oid)[LOCAL].exists == local_expected
    log.info("TABLE 2\n%s", sync.state.pretty_print())

    sync.run(until=lambda: not sync.busy, timeout=3)
    log.info("TABLE 3\n%s", sync.state.pretty_print())

    if local.oid_is_path:
        # missing events for oid_is_path should never happen, and if they do, we re-vivify the missing files
        # this is for safety
        assert local.exists_path('/local/d')
        assert local.exists_path('/local/d/a')
    else:
        # missing events for oid_is_oid may happen (onedrive, gdrive do this)
        # however, the object id is unique and will never be reused, so we know not to recreate
        assert not local.exists_path('/local/d')
        assert not local.exists_path('/local/d/a')


def test_delete_out_of_order_events(sync):
    (local, remote) = sync.providers

    (
        (lf, rf),
        (la, ra),
        (lb, rb),
    ) = setup_remote_local(sync, "f/", "f/a", "f/b")

    local.delete(la.oid)
    local.delete(lb.oid)
    local.delete(lf.oid)

    sync.create_event(LOCAL, FILE, path="/local/f/a", oid=la.oid, exists=False)
    sync.create_event(LOCAL, FILE, path="/local/f/b", oid=lb.oid, exists=False)
    sync.create_event(LOCAL, FILE, path="/local/f/b", oid=lb.oid, exists=True)  # liar!
    sync.create_event(LOCAL, FILE, path="/local/f", oid=lf.oid, exists=False)

    log.info("TABLE 0\n%s", sync.state.pretty_print())

    sync.run(until=lambda:not remote.info_path("/remote/f"), timeout=2)

    log.info("TABLE 2\n%s", sync.state.pretty_print())

    assert not remote.info_path("/remote/f")


def test_sync_unknown_ex(sync):
    (local, remote) = sync.providers

    (
        (lf, _rf),
    ) = setup_remote_local(sync, "a")

    local.delete(lf.oid)

    sync.create_event(LOCAL, FILE, path="/local/a", oid=lf.oid, exists=False)
    with patch.object(remote, "delete", side_effect=lambda *a, **kw: 4/0):
        # all exceptions are converted to backoff errors
        with pytest.raises(_BackoffError):
            sync.do()
            sync.do()

    # and then everything is ok
    sync.run(until=lambda:not remote.info_path("/remote/a"), timeout=2)
    log.info("TABLE 2\n%s", sync.state.pretty_print())


def test_sync_fnf_during_sync(sync):
    (local, _remote) = sync.providers
    setup_remote_local(sync)

    lb = local.create("/local/b", BytesIO(b'hello'))
    sync.create_event(LOCAL, FILE, path="/local/b", oid=lb.oid, exists=True, hash=local.hash_data(BytesIO(b'hello')))

    # just deletes local temp and retries - no backoff
    def fnf(*a, **k):
        raise FileNotFoundError

    # temp error
    def perm(*a, **k):
        raise PermissionError

    sync.nothing_happened = MagicMock()
    sync.process_notifications()
    log.info("notif 1 %s", sync.notifications)
    sync.notifications.clear()

    with patch.object(local, "download", side_effect=fnf),\
            patch.object(SideState, "clean_temp") as ct:
        sync.do()
        sync.do()
        ct.assert_called()

    sync.process_notifications()
    log.info("notif 2 %s", sync.notifications)
    assert not sync.notifications

    # when nothing happens, not even an exception, the nothing_happened flag gets set
    # this prevents backoff from being cleared on noop
    sync.nothing_happened.assert_called()

    with pytest.raises(_BackoffError):
        with patch.object(local, "download", side_effect=perm):
            sync.do()
            sync.do()

    # dump notification queue
    sync.process_notifications()

    log.info("notif %s", sync.notifications)

    assert sync.notifications[0].ntype == NotificationType.TEMPORARY_ERROR

    sync.run_until_found((REMOTE, "remote/b"))


@pytest.mark.parametrize("unverif", [True, False])
def test_sync_change_count(sync, unverif):
    (local, _remote) = sync.providers

    (
        (la, _ra),
    ) = setup_remote_local(sync, "a")

    local.delete(la.oid)

    lb = local.create("/local/b", BytesIO(b'hello'))

    # ignored event for verified counts, but not ignored for raw counts
    sync.create_event(LOCAL, FILE, path="/local/a", oid=la.oid, exists=False)
    # new file event, counted for both
    sync.create_event(LOCAL, FILE, path="/local/b", oid=lb.oid, exists=True, hash=local.hash_data(BytesIO(b'hello')))
    # irrelevant event, ignored for both
    sync.create_event(LOCAL, FILE, path="/irrelevant/a", oid=la.oid, exists=True)

    log.info("TABLE 2\n%s", sync.state.pretty_print())
    if unverif:
        assert sync.change_count(unverified=unverif) == 2
    else:
        assert sync.change_count(unverified=unverif) == 1

def test_create_file_exists_to_name_error(sync):
    (local, remote) = sync.providers

    local_parent = "/local"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"

    local.mkdir(local_parent)
    linfo1 = local.create(local_file1, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)

    _create = remote.create
    called = False

    def _called(sync, synced, translated_path):
        nonlocal called
        called = True

    # Create throws CloudFileExistsError even though directory doesn't exist
    def _create_w_error(name, data):
        nonlocal called, remote_file1
        if name == remote_file1:
            raise CloudFileExistsError("File exists error")
        return _create(name, data)

    # Ensure this situation is handled as a file name error
    sync.handle_file_name_error = _called

    with patch.object(remote, "create", new=_create_w_error):
        sync.run(until=lambda: called, timeout=3)

def test_hash_diff_file_name_error(sync):
    (local, remote) = sync.providers

    local_parent = "/local"
    local_file1 = "/local/file"
    remote_file1 = "/remote/file"

    local.mkdir(local_parent)
    info1 = local.create(local_file1, BytesIO(b"hello"))

    sync.create_event(LOCAL, FILE, path=local_file1, oid=info1.oid, hash=info1.hash)
    sync.run(until=lambda: remote.exists_path(remote_file1), timeout=2)

    info2 = local.upload(info1.oid, BytesIO(b"goodbye"))
    sync.create_event(LOCAL, FILE, path=local_file1, oid=info2.oid, hash=info2.hash)

    def _raise(*args):
        raise CloudFileNameError("invalid name")

    with patch.object(remote, "upload", new=_raise):
        sync.run(until=lambda: not sync.busy, timeout=3)

    check = BytesIO()
    remote.download_path(remote_file1, check)
    assert check.getvalue() == b"hello"
    assert sync.state.lookup_oid(LOCAL, info2.oid).ignored == IgnoreReason.IRRELEVANT


# TODO: test to confirm that a sync with an updated path name that is different but matches the old name will be ignored (eg: a/b -> a\b)
