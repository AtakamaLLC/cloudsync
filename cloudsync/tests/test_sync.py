import logging
from io import BytesIO
import pytest
from typing import NamedTuple, List

from cloudsync.tests.fixtures import WaitFor, RunUntilHelper
from cloudsync import SyncManager, SyncState, CloudFileNotFoundError, LOCAL, REMOTE, FILE, DIRECTORY
from cloudsync.provider import Provider
from cloudsync.types import OInfo
from cloudsync.sync.state import SideState


log = logging.getLogger(__name__)

TIMEOUT = 4


class SyncMgrMixin(SyncManager, RunUntilHelper):
    pass


def make_sync(request, mock_provider_generator, shuffle):
    shuffle = shuffle

    providers = (mock_provider_generator(), mock_provider_generator(oid_is_path=False))

    state = SyncState(providers, shuffle=shuffle)

    def translate(to, path):
        if to == LOCAL:
            return "/local" + path.replace("/remote", "")

        if to == REMOTE:
            return "/remote" + path.replace("/local", "")

        raise ValueError("bad path: %s", path)

    def resolve(f1, f2):
        return None

    # two providers and a translation function that converts paths in one to paths in the other
    sync = SyncMgrMixin(state, providers, translate, resolve)

    yield sync

    sync.state.assert_index_is_correct()

    sync.done()


@pytest.fixture(name="sync")
def fixture_sync(request, mock_provider_generator):
    yield from make_sync(request, mock_provider_generator, True)

@pytest.fixture(name="sync_sh", params=[0, 1], ids=["sh0", "sh1"])
def fixture_sync_sh(request, mock_provider_generator):
    yield from make_sync(request, mock_provider_generator, request.param)

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.change_state(LOCAL, FILE, oid=linfo.oid, exists=True)

    assert sync.state.entry_count() == 1
    assert sync.state.changeset_len == 1
    assert sync.change_count(REMOTE) == 0
    assert sync.change_count(LOCAL) == 1

    rinfo = sync.providers[REMOTE].create(remote_path2, BytesIO(b"hello2"))

    # inserts info about some cloud path
    sync.change_state(REMOTE, FILE, oid=rinfo.oid,
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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    new_oid = sync.providers[LOCAL].rename(linfo.oid, local_path2)

    sync.change_state(LOCAL, FILE, path=local_path2,
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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    linfo = sync.providers[LOCAL].upload(linfo.oid, BytesIO(b"hello2"))

    sync.change_state(LOCAL, FILE, linfo.oid, hash=linfo.hash)

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    sync.providers[LOCAL].delete(linfo.oid)
    sync.change_state(LOCAL, FILE, linfo.oid, exists=False)

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
    sync.change_state(LOCAL, DIRECTORY, path=local_dir1,
                      oid=local_dir_oid1)
    sync.change_state(LOCAL, DIRECTORY, path=local_path1,
                      oid=local_path_oid1)

    sync.run_until_found((REMOTE, remote_dir1))
    sync.run_until_found((REMOTE, remote_path1))

    log.debug("BEFORE DELETE\n %s", sync.state.pretty_print())

    sync.providers[LOCAL].delete(local_path_oid1)
    sync.change_state(LOCAL, FILE, local_path_oid1, exists=False)

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)
    sync.change_state(REMOTE, FILE, path=remote_path1,
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

    sync.providers[LOCAL].log_debug_state("LOCAL")              # type: ignore
    sync.providers[REMOTE].log_debug_state("REMOTE")            # type: ignore

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)
    sync.change_state(REMOTE, FILE, path=remote_path1,
                      oid=rinfo.oid, hash=rinfo.hash)

    # ensure events are flushed a couple times
    sync.run(until=lambda: not sync.state.changeset_len, timeout=1)

    sync.providers[LOCAL].log_debug_state("LOCAL")      # type: ignore
    sync.providers[REMOTE].log_debug_state("REMOTE")    # type: ignore

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo.oid, hash=linfo.hash)

    sync.run_until_found((REMOTE, remote_path1))

    rinfo = sync.providers[REMOTE].info_path(remote_path1)

    assert len(sync.state.get_all()) == 1

    ent = sync.state.get_all().pop()

    sync.providers[REMOTE].log_debug_state("BEFORE")        # type: ignore

    new_oid_l = sync.providers[LOCAL].rename(linfo.oid, local_path2)
    new_oid_r = sync.providers[REMOTE].rename(rinfo.oid, remote_path2)

    sync.providers[REMOTE].log_debug_state("AFTER")         # type: ignore

    sync.change_state(LOCAL, FILE, path=local_path2,
                      oid=new_oid_l, hash=linfo.hash, prior_oid=linfo.oid)

    assert len(sync.state.get_all()) == 1
    assert ent[REMOTE].oid == new_oid_r

    sync.change_state(REMOTE, FILE, path=remote_path2,
                      oid=new_oid_r, hash=rinfo.hash, prior_oid=rinfo.oid)

    assert len(sync.state.get_all()) == 1

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    # currently defers to the alphabetcially greater name, rather than conflicting
    sync.run_until_found((LOCAL, "/local/stuff-r"))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    assert not sync.providers[LOCAL].exists_path(local_path1)
    assert not sync.providers[LOCAL].exists_path(local_path2)
    sync.state.assert_index_is_correct()


def test_sync_cycle(sync: SyncMgrMixin):
    l_parent = "/local"
    r_parent = "/remote"
    lp1, lp2, lp3 = "/local/a", "/local/b", "/local/c",
    rp1, rp2, rp3 = "/remote/a", "/remote/b", "/remote/c",
    templ = "/local/d"

    sync.providers[LOCAL].mkdir(l_parent)
    sync.providers[REMOTE].mkdir(r_parent)

    linfo1 = sync.providers[LOCAL].create(lp1, BytesIO(b"hello1"))
    sync.change_state(LOCAL, FILE, path=lp1, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, rp1), timeout=1)
    rinfo1 = sync.providers[REMOTE].info_path(rp1)

    linfo2 = sync.providers[LOCAL].create(lp2, BytesIO(b"hello2"))
    sync.change_state(LOCAL, FILE, path=lp2, oid=linfo2.oid, hash=linfo2.hash)
    sync.run_until_found((REMOTE, rp2))
    rinfo2 = sync.providers[REMOTE].info_path(rp2)

    linfo3 = sync.providers[LOCAL].create(lp3, BytesIO(b"hello3"))
    sync.change_state(LOCAL, FILE, path=lp3, oid=linfo3.oid, hash=linfo3.hash)
    sync.run_until_found((REMOTE, rp3))
    rinfo3 = sync.providers[REMOTE].info_path(rp3)

    sync.providers[REMOTE].log_debug_state("BEFORE")                # type: ignore
    tmp1oid = sync.providers[LOCAL].rename(linfo1.oid, templ)
    lp1oid = sync.providers[LOCAL].rename(linfo3.oid, lp1)
    lp3oid = sync.providers[LOCAL].rename(linfo2.oid, lp3)
    lp2oid = sync.providers[LOCAL].rename(tmp1oid, lp2)

    # a->temp, c->a, b->c, temp->b

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.change_state(LOCAL, FILE, path=templ, oid=tmp1oid, hash=linfo1.hash, prior_oid=linfo1.oid)
    log.debug("TABLE 1:\n%s", sync.state.pretty_print())
    sync.change_state(LOCAL, FILE, path=lp1, oid=lp1oid, hash=linfo3.hash, prior_oid=linfo3.oid)
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())
    sync.change_state(LOCAL, FILE, path=lp3, oid=lp3oid, hash=linfo2.hash, prior_oid=linfo2.oid)
    log.debug("TABLE 3:\n%s", sync.state.pretty_print())
    sync.change_state(LOCAL, FILE, path=lp2, oid=lp2oid, hash=linfo1.hash, prior_oid=tmp1oid)
    log.debug("TABLE 4:\n%s", sync.state.pretty_print())
    assert len(sync.state.get_all()) == 3
    sync.providers[REMOTE].log_debug_state("MIDDLE")                # type: ignore

    sync.run(until=lambda: not sync.state.changeset_len, timeout=1)
    sync.providers[REMOTE].log_debug_state("AFTER")                 # type: ignore

    i1 = sync.providers[REMOTE].info_path(rp1)
    i2 = sync.providers[REMOTE].info_path(rp2)
    i3 = sync.providers[REMOTE].info_path(rp3)

    assert i1 and i2 and i3

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
    sync.change_state(LOCAL, FILE, path=local_path1,
                      oid=linfo1.oid, hash=linfo1.hash)

    sync.change_state(REMOTE, FILE, path=remote_path2,
                      oid=rinfo2.oid, hash=rinfo2.hash)

    sync.run_until_found((REMOTE, remote_path1), (LOCAL, local_path2))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    new_oid1 = sync.providers[LOCAL].rename(linfo1.oid, local_path3)
    prior_oid = sync.providers[LOCAL].oid_is_path and linfo1.oid
    sync.change_state(LOCAL, FILE, path=local_path3, oid=new_oid1, prior_oid=prior_oid)

    new_oid2 = sync.providers[REMOTE].rename(rinfo2.oid, remote_path3)
    prior_oid = sync.providers[REMOTE].oid_is_path and rinfo2.oid
    sync.change_state(REMOTE, FILE, path=remote_path3, oid=new_oid2, prior_oid=prior_oid)

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    ok = lambda: (
        sync.providers[REMOTE].exists_path("/remote/stuff.conflicted")
        or
        sync.providers[LOCAL].exists_path("/local/stuff.conflicted")
    )
    sync.run(until=ok, timeout=3)

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    assert ok()


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
    sync.change_state(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)
    sync.run_until_found((REMOTE, remote_file1))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    folder_oid = sync.providers[LOCAL].mkdir(local_folder)
    sync.change_state(LOCAL, DIRECTORY, path=local_folder, oid=folder_oid, hash=None)

    new_oid = sync.providers[LOCAL].rename(linfo1.oid, local_file2)
    sync.change_state(LOCAL, FILE, path=local_file2, oid=new_oid, hash=linfo1.hash, prior_oid=linfo1.oid)

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
    sync.change_state(REMOTE, FILE, path=remote_file1, oid=rinfo1.oid, hash=rinfo1.hash)
    sync.run_until_found((LOCAL, local_file1))

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())

    folder_oid = sync.providers[REMOTE].mkdir(remote_folder)
    sync.change_state(REMOTE, DIRECTORY, path=remote_folder, oid=folder_oid, hash=None)

    sync.providers[REMOTE].rename(rinfo1.oid, remote_file2)
    sync.change_state(REMOTE, FILE, path=remote_file2, oid=rinfo1.oid, hash=rinfo1.hash)

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
    sync.change_state(source, DIRECTORY, path=folder1[source], oid=folder_oid, hash=None)

    file_info: OInfo = sync.providers[source].create(file1[source], BytesIO(b"hello"))
    sync.change_state(source, FILE, path=file1[source], oid=file_info.oid, hash=None)

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.run_until_found((dest, folder1[dest]))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    new_oid = sync.providers[source].rename(folder_oid, folder2[source])
    sync.change_state(source, DIRECTORY, path=folder2[source], oid=new_oid, hash=None, prior_oid=folder_oid)

    log.debug("TABLE 2:\n%s", sync.state.pretty_print())
    sync.run_until_found(
        (source, file2[source]),
        (dest, file2[dest])
    , threaded=True)
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
    sync.change_state(LOCAL, FILE, path=local_file1, oid=linfo1.oid, hash=linfo1.hash)
    sync.do()
    sync.do()
    sync.do()
    log.debug("TABLE 2:\n%s", sync.state.pretty_print())

    assert not sync.providers[REMOTE].info_path(local_file1)

    sync.run_until_found((REMOTE, remote_file1), timeout=2)

    assert sync.providers[REMOTE].info_path(remote_file1)

    sync.aging = 0
    linfo2 = sync.providers[LOCAL].create(local_file2, BytesIO(b"hello"))
    sync.change_state(LOCAL, FILE, path=local_file2, oid=linfo2.oid, hash=linfo2.hash)
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
    sync.change_state(LOCAL, DIRECTORY, path=folder1[LOCAL], oid=folder_oid, hash=None)

    file_info: OInfo = sync.providers[LOCAL].create(file1[LOCAL], BytesIO(b"hello"))
    sync.change_state(LOCAL, FILE, path=file1[LOCAL], oid=file_info.oid, hash=None)

    log.debug("TABLE 0:\n%s", sync.state.pretty_print())
    sync.run_until_found((REMOTE, file1[REMOTE]))

    log.debug("TABLE 1:\n%s", sync.state.pretty_print())

    sync.providers[LOCAL].delete(file_info.oid)
    sync.providers[LOCAL].delete(folder_oid)

    sync.change_state(LOCAL, DIRECTORY, oid=file_info.oid, exists=False)
    sync.change_state(LOCAL, DIRECTORY, oid=folder_oid, exists=False)

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

    sync.change_state(LOCAL, DIRECTORY, path=local_dir,
                      oid=ldir)
    sync.change_state(LOCAL, FILE, path=local_file,
                      oid=lfile.oid, hash=lfile.hash)

    sync.run_until_found((REMOTE, remote_file), (REMOTE, remote_dir))

    rfile = sync.providers[REMOTE].info_path(remote_file)
    sync.providers[REMOTE].delete(rfile.oid)
    sync.providers[REMOTE].delete(rdir)

    # Directory delete - should punt because of children
    sync.aging = 0
    sync.change_state(REMOTE, DIRECTORY, path=remote_dir, oid=rdir, exists=False)
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(ldir))) == 1

    # Next action should be on deleted child (detected in above)
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(ldir))) == 0

    # Now it should successfully rmdir
    sync.do()
    assert len(list(sync.providers[LOCAL].listdir(lparent))) == 0

    sync.state.assert_index_is_correct()



# TODO: test to confirm that a file that is both a rename and an update will be both renamed and updated
# TODO: test to confirm that a sync with an updated path name that is different but matches the old name will be ignored (eg: a/b -> a\b)
