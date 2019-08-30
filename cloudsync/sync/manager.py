import os
import logging
import tempfile
import shutil
import time

from typing import Tuple, Optional

from cloudsync.provider import Provider

__all__ = ['SyncManager']

from cloudsync.exceptions import CloudFileNotFoundError, CloudFileExistsError, CloudTemporaryError
from cloudsync.types import DIRECTORY, FILE
from cloudsync.runnable import Runnable
from cloudsync.log import TRACE

from .state import SyncState, SyncEntry, SideState, TRASHED, EXISTS, LOCAL, REMOTE, UNKNOWN
from .util import debug_sig

log = logging.getLogger(__name__)

# useful for converting oids and pointer nubmers into digestible nonces

FINISHED = 1
REQUEUE = 0


def other_side(index):
    return 1-index


class ResolveFile():
    def __init__(self, info, provider):
        self.info = info
        self.provider = provider
        self.path = info.path
        self.side = info.side
        self.otype = info.otype
        self.temp_file = info.temp_file
        if self.otype == FILE:
            assert info.temp_file
        self.__fh = None

    @property
    def fh(self):
        if not self.__fh:
            if not os.path.exists(self.info.temp_file):
                try:
                    with open(self.info.temp_file, "wb") as f:
                        self.provider.download(self.info.oid, f)
                except Exception as e:
                    log.debug("error downloading %s", e)
                    try:
                        os.unlink(self.info.temp_file)
                    except FileNotFoundError:
                        pass
                    raise

            self.__fh = open(self.info.temp_file, "rb")
        return self.__fh

    def read(self, *a):
        return self.fh.read(*a)

    def write(self, buf):
        return self.fh.write(buf)

    def close(self):
        return self.fh.close()

    def seek(self, *a):
        return self.fh.seek(*a)


class SyncManager(Runnable):  # pylint: disable=too-many-public-methods, too-many-instance-attributes
    def __init__(self, state, providers: Tuple[Provider, Provider], translate, resolve_conflict, sleep=None):
        self.state: SyncState = state
        self.providers: Tuple[Provider, Provider] = providers
        self.translate = translate
        self.__resolve_conflict = resolve_conflict
        self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")

        if not sleep:
            # these are the event sleeps, but really we need more info than this
            sleep = (self.providers[LOCAL].default_sleep, self.providers[REMOTE].default_sleep)

        self.sleep = sleep

        # TODO: we need sync_aging, backoff_min, backoff_max, backoff_mult documented with an interface and tests!

        ####
        self.min_backoff = 0
        self.max_backoff = 0
        self.backoff = 0

        max_sleep = max(sleep)                    # on sync fail, use the worst time for backoff

        self.aging = max_sleep / 5                # how long before even trying to sync

        self.min_backoff = max_sleep / 10.0       # event sleep of 15 seconds == 1.5 second backoff on failures
        self.max_backoff = max_sleep * 4.0        # escalating up to a 1 minute wait time
        self.backoff = self.min_backoff
        self.mult_backoff = 2

        assert len(self.providers) == 2

    def set_resolver(self, resolver):
        self.__resolve_conflict = resolver

    def do(self):
        with self.state.lock:
            sync: SyncEntry = self.state.change(self.aging)

            if sync:
                try:
                    self.sync(sync)
                    self.state.storage_update(sync)
                    self.backoff = self.min_backoff
                except CloudTemporaryError as e:
                    log.error(
                        "exception %s[%s] while processing %s, %i", type(e), e, sync, sync.punted)
                    sync.punt()
                    time.sleep(self.backoff)
                    self.backoff = min(self.backoff * self.mult_backoff, self.max_backoff)
                except Exception as e:
                    log.exception(
                        "exception %s[%s] while processing %s, %i", type(e), e, sync, sync.punted, stack_info=True)
                    sync.punt()
                    time.sleep(self.backoff)
                    self.backoff = min(self.backoff * self.mult_backoff, self.max_backoff)

    def done(self):
        log.info("cleanup %s", self.tempdir)
        shutil.rmtree(self.tempdir)

    def get_latest_state(self, ent):
        log.log(TRACE, "before update state %s", ent)
        for i in (LOCAL, REMOTE):
            if not ent[i].changed:
                continue

            info = self.providers[i].info_oid(ent[i].oid, use_cache=False)

            if not info:
                continue

            ent[i].exists = EXISTS
            ent[i].hash = info.hash
            ent[i].otype = info.otype

            if ent[i].otype == FILE:
                if ent[i].hash is None:
                    ent[i].hash = self.providers[i].hash_oid(ent[i].oid)

                if ent[i].exists == EXISTS:
                    if ent[i].hash is None:
                        log.warning("Cannot sync %s, since hash is None", ent[i])

            if ent[i].path != info.path:
                self.update_entry(ent, oid=ent[i].oid, side=i, path=info.path)

        log.log(TRACE, "after update state %s", ent)

    def path_conflict(self, ent):
        # both are synced
        if ent[0].path and ent[1].path and ent[0].sync_hash and ent[1].sync_hash:
            return not self.providers[0].paths_match(ent[0].path, ent[0].sync_path) and \
                not self.providers[1].paths_match(ent[1].path, ent[1].sync_path)
        return False

    def sync(self, sync):
        self.get_latest_state(sync)

        if sync.hash_conflict():
            log.debug("handle hash conflict")
            self.handle_hash_conflict(sync)
            return

        if self.path_conflict(sync):
            log.debug("handle path conflict")
            self.handle_path_conflict(sync)
            return

        log.log(TRACE, "table\r\n%s", self.state.pretty_print())

        for i in (LOCAL, REMOTE):
            if sync[i].changed:
                if sync[i].hash is None and sync[i].otype == FILE and sync[i].exists == EXISTS:
                    log.debug("ignore %s", sync)
                    # no hash for file, ignore it
                    self.finished(i, sync)
                    break
                    
                response = self.embrace_change(sync, i, other_side(i))
                if response == FINISHED:
                    self.finished(i, sync)
                break
#        self.state.repair_index()
#        self.state.assert_index_is_correct()

    def temp_file(self):
        if not os.path.exists(self.tempdir):
            # in case user deletes it... recreate
            self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")
        # prefer big random name over NamedTemp which can infinite loop
        ret = os.path.join(self.tempdir, os.urandom(16).hex())
        log.debug("tempdir %s -> %s", self.tempdir, ret)
        return ret

    def finished(self, side, sync):
        sync[side].changed = 0
        self.state.finished(sync)
        self.clean_temps(sync)

    @staticmethod
    def clean_temps(sync):
        # todo: move this to the sync obj
        for side in (LOCAL, REMOTE):
            if sync[side].temp_file:
                try:
                    os.unlink(sync[side].temp_file)
                except FileNotFoundError:
                    pass
                except OSError as e:
                    log.debug("exception unlinking %s", e)
                except Exception as e:  # any exceptions here are pointless
                    log.warning("exception unlinking %s", e)
                sync[side].temp_file = None

    def download_changed(self, changed, sync):
        sync[changed].temp_file = sync[changed].temp_file or self.temp_file()

        assert sync[changed].oid

        if os.path.exists(sync[changed].temp_file):
            return True

        try:
            partial_temp = sync[changed].temp_file + ".tmp"
            log.debug("%s download %s to %s", self.providers[changed], sync[changed].oid, partial_temp)
            with open(partial_temp, "wb") as f:
                self.providers[changed].download(sync[changed].oid, f)
            os.rename(partial_temp, sync[changed].temp_file)
            return True
        except PermissionError as e:
            raise CloudTemporaryError("download or rename exception %s" % e)

        except CloudFileNotFoundError:
            log.debug("download from %s failed fnf, switch to not exists",
                      self.providers[changed].name)
            sync[changed].exists = TRASHED
            return False

    def mkdir_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        # see if there are other entries for the same path, but other ids
        ents = list(self.state.lookup_path(changed, sync[changed].path))
        ents = [ent for ent in ents if ent != sync]
        if ents:
            for ent in ents:
                if ent[changed].otype == DIRECTORY:
                    # these we can toss, they are other folders
                    # keep the current one, since it exists for sure
                    log.debug("discard %s", ent)
                    self.discard_entry(ent)

        ents = [ent for ent in ents if not ent.discarded]
        ents = [ent for ent in ents if TRASHED not in (
            ent[changed].exists, ent[synced].exists)]

        if ents:
            if not sync.punted:
                log.debug("punt mkdir")
                sync.punt()
                return REQUEUE

            raise NotImplementedError(
                "What to do if we create a folder when there's already a FILE")

        try:
            log.debug("translated %s as path %s",
                      sync[changed].path, translated_path)

            # could have made a dir that already existed on my side or other side

            chents = list(self.state.lookup_path(changed, sync[changed].path))
            syents = list(self.state.lookup_path(synced, translated_path))
            notme_chents = [ent for ent in chents if ent != sync]

            conflicts = []
            for ent in notme_chents:
                # dup dirs on remote side can be ignored
                if ent[synced].otype == DIRECTORY:
                    log.debug("discard duplicate dir entry, caused by a mkdirs %s", ent)
                    self.discard_entry(ent)
                else:
                    conflicts.append(ent)

            # if a file exists with the same name on the sync side
            conflicts = [ent for ent in syents if ent[synced].exists != TRASHED and ent != sync]

            # TODO: check for a cycle here. If there is a cycle this will never sync up. see below comment for more info
            if conflicts:
                log.info("mkdir conflict %s letting other side handle it", sync)
                return FINISHED

            # make the dir
            oid = self.providers[synced].mkdirs(translated_path)
            log.debug("mkdir %s as path %s oid %s",
                      self.providers[synced].name, translated_path, debug_sig(oid))

            # did i already have that oid? if so, chuck it
            already_dir = self.state.lookup_oid(synced, oid)
            if already_dir and already_dir != sync and already_dir[synced].otype == DIRECTORY:
                log.debug("discard %s", already_dir)
                self.discard_entry(already_dir)

            sync[synced].sync_path = translated_path
            sync[changed].sync_path = sync[changed].path

            self.update_entry(
                sync, synced, exists=True, oid=oid, path=translated_path)

            return FINISHED
        except CloudFileNotFoundError:
            if not sync.punted:
                sync.punt()
                return REQUEUE

            log.debug("mkdir %s : %s failed fnf, TODO fix mkdir code and stuff",
                      self.providers[synced].name, translated_path)
            raise NotImplementedError("TODO mkdir, and make state etc")

    def upload_synced(self, changed, sync):
        assert sync[changed].temp_file

        synced = other_side(changed)
        try:
            info = self.providers[synced].upload(
                sync[synced].oid, open(sync[changed].temp_file, "rb"))
            log.debug("upload to %s as path %s",
                      self.providers[synced].name, sync[synced].sync_path)

            sync[synced].hash = info.hash
            sync[synced].sync_hash = info.hash
            if info.path:
                sync[synced].sync_path = info.path
            else:
                sync[synced].sync_path = sync[synced].path
            sync[changed].sync_hash = sync[changed].hash
            sync[changed].sync_path = sync[changed].path

            self.update_entry(
                sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path)
            return True
        except FileNotFoundError:
            return False
        except CloudFileNotFoundError:
            info = self.providers[synced].info_oid(sync[synced].oid)

            log.debug("upload to %s failed fnf, TODO fix mkdir code and stuff, info: %s",
                      self.providers[synced].name, info)

            if not info:
                log.debug("convert to unsynced")
                sync[synced].exists = TRASHED
            return False
        except CloudFileExistsError:
            # this happens if the remote oid is a folder
            log.debug("split bc upload to folder")

            defer_ent, defer_side, replace_ent, replace_side \
                = self.state.split(sync)

            return self.handle_split_conflict(
                defer_ent, defer_side, replace_ent, replace_side)

    def _create_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        log.debug("create on %s as path %s",
                  self.providers[synced].name, translated_path)
        try:
            with open(sync[changed].temp_file, "rb") as f:
                info = self.providers[synced].create(translated_path, f)
            log.debug("created %s", info)
        except CloudFileExistsError:
            log.debug("exists error %s", translated_path)
            info = self.providers[synced].info_path(translated_path)
            if not info:
                raise
            with open(sync[changed].temp_file, "rb") as f:
                existing_hash = self.providers[synced].hash_data(f)
            if existing_hash != info.hash:
                raise
            log.debug("use existing %s", info)
        except Exception as e:
            log.debug("failed to create %s, %s", translated_path, e)
            raise

        assert info.hash
        assert sync[changed].hash
        sync[synced].sync_hash = info.hash
        if info.path:
            sync[synced].sync_path = info.path
        else:
            sync[synced].sync_path = translated_path
        sync[changed].sync_hash = sync[changed].hash
        sync[changed].sync_path = sync[changed].path
        self.update_entry(sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path, hash=info.hash)

    def update_entry(self, ent, side, oid, *, path=None, hash=None, exists=True, changed=False, otype=None):  # pylint: disable=redefined-builtin
        # updates entry without marking as changed unless explicit
        # used internally
        self.state.update_entry(ent, side, oid, path=path, hash=hash, exists=exists, changed=changed, otype=otype)

    def change_state(self, side, otype, oid, *, path=None, hash=None, exists=True, prior_oid=None):  # pylint: disable=redefined-builtin
        # looks up oid and changes state, marking changed as if it's an event
        # used only for testing
        self.state.update(side, otype, oid, path=path, hash=hash, exists=exists, prior_oid=prior_oid)

    def create_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        try:
            self._create_synced(changed, sync, translated_path)
            return FINISHED
        except CloudFileNotFoundError:
            # parent presumably exists
            parent = self.providers[changed].dirname(sync[changed].path)
            log.debug("make %s first before %s", parent, sync[changed].path)
            ents = self.state.lookup_path(changed, parent)
            if not ents: 
                info = self.providers[changed].info_path(parent)
                if info:
                    self.state.update(changed, DIRECTORY, info.oid, path=parent)
                else:
                    log.info("no info and no dir, ignoring?")

            else:
                if not ents[0][changed].changed:
                    self.update_entry(ents[0], changed, ents[0][changed].oid, changed=True)
                    log.debug("updated entry %s", parent)
                
            sync.punt()
            return REQUEUE
        except CloudFileExistsError:
            # there's a file or folder in the way, let that resolve if possible
            log.debug("can't create %s, try punting", translated_path)

            if sync.punted > 0:
                info = self.providers[synced].info_path(translated_path)
                if not info:
                    log.debug("got a file exists, and then it didn't exist %s", sync)
                    sync.punt()
                    return REQUEUE

                sync[synced].oid = info.oid
                sync[synced].hash = info.hash
                sync[synced].path = translated_path
                self.update_entry(sync, synced, info.oid, path=translated_path)
                # maybe it's a hash conflict
                sync.punt()
                return REQUEUE
            else:
                # maybe it's a name conflict
                sync.punt()
            return REQUEUE

    def __resolve_file_likes(self, side_states):
        fhs = []
        for ss in side_states:
            assert type(ss) is SideState

            if not ss.temp_file and ss.otype == FILE:
                ss.temp_file = self.temp_file()

            fhs.append(ResolveFile(ss, self.providers[ss.side]))

            assert ss.oid
        return fhs

    def __safe_call_resolver(self, fhs):
        if DIRECTORY in (fhs[0].otype, fhs[1].otype):
            if fhs[0].otype != fhs[1].otype:
                if fhs[0].otype == DIRECTORY:
                    fh = fhs[0]
                else:
                    fh = fhs[1]
            # for simplicity: directory conflicted with file, always favors directory
            return (fh, True)

        is_file_like = lambda f: hasattr(f, "read") and hasattr(f, "close")
        ret = None
        try:
            ret = self.__resolve_conflict(*fhs)
            if ret:
                if len(ret) != 2:
                    log.error("bad return value for resolve conflict %s", ret)
                    ret = None
                if not is_file_like(ret[0]):
                    log.error("bad return value for resolve conflict %s", ret)
                    ret = None
        except Exception as e:
            log.exception("exception during conflict resolution %s", e)

        if ret is None:
            # we defer to the remote... since this can prevent loops
            if fhs[0].side == REMOTE:
                ret = (fhs[0], True)
            else:
                ret = (fhs[1], True)

        return ret

    def __resolver_merge_upload(self, side_states, fh, keep):
        # we modified to both sides, need to merge the entries
        ent1, ent2 = side_states

        defer_ent = self.state.lookup_oid(ent1.side, ent1.oid)
        replace_ent = self.state.lookup_oid(ent2.side, ent2.oid)

        if keep:
            # both sides are being kept, so we have to upload since there are no entries
            fh.seek(0)
            info1 = self.providers[ent1.side].create(ent1.path, fh)
            fh.seek(0)
            info2 = self.providers[ent2.side].create(ent2.path, fh)

            ent1.oid = info1.oid
            ent2.oid = info2.oid

            self.update_entry(defer_ent, ent1.side, ent1.oid, path=ent1.path, hash=ent1.hash)

            ent1 = defer_ent[ent1.side]
            ent2 = defer_ent[ent2.side]

            assert info2.hash
            assert info1.hash
            ent2.sync_hash = info2.hash
            ent2.sync_path = info2.path
            ent1.sync_hash = info1.hash
            ent1.sync_path = info1.path

        # in case oids have changed
        self.update_entry(defer_ent, ent2.side, ent2.oid, path=ent2.path, hash=ent2.hash)

        defer_ent[ent2.side].sync_hash = ent2.sync_hash
        defer_ent[ent2.side].sync_path = ent2.sync_path
        self.discard_entry(replace_ent)

    def resolve_conflict(self, side_states):  # pylint: disable=too-many-statements
        fhs = self.__resolve_file_likes(side_states)

        fh, keep = self.__safe_call_resolver(fhs)

        log.debug("got ret side %s", getattr(fh, "side", None))

        defer = None

        for i, rfh in enumerate(fhs):
            this = side_states[i]
            that = side_states[1-i]

            if fh is not rfh:
                # user didn't opt to keep my rfh
                log.debug("replacing %s", this.side)
                if not keep:
                    fh.seek(0)
                    info2 = self.providers[this.side].upload(this.oid, fh)
                    this.hash = info2.hash
                    assert info2.hash
                    that.sync_hash = that.hash
                    that.sync_path = that.path
                    this.sync_hash = this.hash
                    this.sync_path = this.path
                else:
                    try:
                        self._resolve_rename(this)
                    except CloudFileNotFoundError:
                        log.debug("there is no conflict, because the file doesn't exist? %s", this)

                if defer is None:
                    defer = that.side
                else:
                    defer = None

        if defer is not None:
            # toss the other side that was replaced
            sorted_states = sorted(side_states, key=lambda e: e.side)
            replace_side = other_side(defer)
            replace_ent = self.state.lookup_oid(replace_side, sorted_states[replace_side].oid)
            if replace_ent:
                self.discard_entry(replace_ent)
        else:
            # both sides were modified....
            self.__resolver_merge_upload(side_states, fh, keep)

        log.debug("RESOLVED CONFLICT: %s dide: %s", side_states, defer)
        log.debug("table\r\n%s", self.state.pretty_print())

    def delete_synced(self, sync, changed, synced):
        log.debug("try sync deleted %s", sync[changed].path)
        # see if there are other entries for the same path, but other ids
        ents = list(self.state.lookup_path(changed, sync[changed].path))
        ents = [ent for ent in ents if ent != sync]
#        ents2 = list(self.state.lookup_path(synced, sync[synced].path))
#        ents += [ent for ent in ents2 if ent != sync]

        for ent in ents:
            if ent.is_creation(synced):
                log.debug("discard delete, pending create %s:%s", synced, ent)
                self.discard_entry(sync)
                return

        if sync[synced].oid:
            try:
                self.providers[synced].delete(sync[synced].oid)
            except CloudFileNotFoundError:
                pass
        else:
            log.debug("was never synced, ignoring deletion")

        sync[synced].exists = TRASHED
        self.discard_entry(sync)

    def check_disjoint_create(self, sync, changed, synced, translated_path):
        # check for creation of a new file with another in the table

        if sync[changed].otype != FILE:
            return False

        ents = list(self.state.lookup_path(synced, translated_path))

        # filter for exists
        other_ents = [ent for ent in ents if ent != sync]
        if not other_ents:
            return False

        log.debug("found matching %s, other ents: %s",
                  translated_path, other_ents)

        # ignoring trashed entries with different oids on the same path
        if all(TRASHED in (ent[synced].exists, ent[changed].exists) for ent in other_ents):
            return False

        other_untrashed_ents = [ent for ent in other_ents if TRASHED not in (
            ent[synced].exists, ent[changed].exists)]

        assert len(other_untrashed_ents) == 1

        log.debug("split conflict found : %s", other_untrashed_ents)

        return self.handle_split_conflict(
            other_untrashed_ents[0], synced, sync, changed)

    def handle_path_change_or_creation(self, sync, changed, synced):  # pylint: disable=too-many-branches, too-many-return-statements
        if not sync[changed].path:
            self.update_sync_path(sync, changed)
            log.debug("NEW SYNC %s", sync)
            if sync[changed].exists == TRASHED or sync.discarded:
                log.debug("requeue trashed event %s", sync)
                return REQUEUE

        translated_path = self.translate(synced, sync[changed].path)
        if translated_path is None:
            # ignore these
            return FINISHED

        if not sync[changed].path:
            log.debug("can't sync, no path %s", sync)

        if sync.is_creation(changed):
            # never synced this before, maybe there's another local path with
            # the same name already?
            if self.check_disjoint_create(sync, changed, synced, translated_path):
                log.debug("disjoint, requeue")
                return REQUEUE

        if sync.is_creation(changed):
            assert not sync[changed].sync_hash
            # looks like a new file

            if sync[changed].otype == DIRECTORY:
                return self.mkdir_synced(changed, sync, translated_path)

            if not self.download_changed(changed, sync):
                return REQUEUE

            if sync[synced].oid and sync[synced].exists != TRASHED:
                if not self.upload_synced(changed, sync):
                    return REQUEUE
            else:
                return self.create_synced(changed, sync, translated_path)
        else:  # handle rename
            if sync[synced].sync_path == translated_path:
                return FINISHED

            log.debug("rename %s %s", sync[synced].sync_path, translated_path)
            try:
                new_oid = self.providers[synced].rename(sync[synced].oid, translated_path)
            except CloudFileNotFoundError as e:
                log.debug("ERROR: can't rename for now %s: %s", sync, e)
                if sync.punted > 5:
                    log.exception("punted too many times, giving up")
                    return FINISHED
                else:
                    log.debug("fnf, punt")
                    sync.punt()
                return REQUEUE
            except CloudFileExistsError:
                log.debug("can't rename, file exists")
                if sync.punted:
                    log.debug("rename for conflict")
                    self.rename_to_fix_conflict(sync, synced, translated_path)
                sync.punt()
                return REQUEUE

            assert sync[synced].sync_hash or sync[synced].otype == DIRECTORY
            assert sync[changed].sync_hash or sync[changed].otype == DIRECTORY
            sync[synced].sync_path = translated_path
            sync[changed].sync_path = sync[changed].path
            self.update_entry(sync, synced, path=translated_path, oid=new_oid)
        return FINISHED

    def _resolve_rename(self, replace):
        replace_ent = self.state.lookup_oid(replace.side, replace.oid)
        if not replace_ent:
            return False

        _old_oid, new_oid, new_name = self.conflict_rename(replace.side, replace.path)
        if new_name is None:
            return False

        self.update_entry(replace_ent, side=replace.side, oid=new_oid)
        return True

    def rename_to_fix_conflict(self, sync, side, path):
        old_oid, new_oid, new_name = self.conflict_rename(side, path)
        if new_name is None:
            return False

        log.debug("rename to fix conflict %s -> %s", sync[side].path, new_name)
        # file can get renamed back, if there's a cycle
        if old_oid == sync[side].oid:
            self.update_entry(sync, side=side, oid=new_oid)
        else:
            ent = self.state.lookup_oid(side, old_oid)
            if ent:
                self.update_entry(ent, side=side, oid=new_oid)

        return True

    def conflict_rename(self, side, path):
        folder, base = self.providers[side].split(path)
        if base == "":
            raise ValueError("bad path %s" % path)

        index = base.find(".")
        if index >= 0:
            ext = base[index:]
            base = base[:index]
        else:
            base = base
            ext = ""

        oinfo = self.providers[side].info_path(path)

        if not oinfo:
            return None, None, None

        i = 1
        new_oid = None
        conflict_name = base + ".conflicted" + ext
        while new_oid is None:
            try:
                conflict_path = self.providers[side].join(folder, conflict_name)
                new_oid = self.providers[side].rename(oinfo.oid, conflict_path)
            except CloudFileExistsError:
                i = i + 1
                conflict_name = base + ".conflicted" + str(i) + ext

        log.debug("conflict renamed: %s -> %s", path, conflict_path)
        return oinfo.oid, new_oid, conflict_path

    def discard_entry(self, sync):
        if sync:
            sync.discard()
            self.state.storage_update(sync)

    def embrace_change(self, sync, changed, synced): # pylint: disable=too-many-return-statements
        if sync.discarded:
            log.warning("discarded!")
            return FINISHED
        log.debug("embrace %s, side:%s", sync, changed)

        if sync[changed].path:
            translated_path = self.translate(synced, sync[changed].path)
            if not translated_path:
                log.log(TRACE, ">>>Not a cloud path %s, discard", sync[changed].path)
                self.discard_entry(sync)
                return FINISHED

            # parent_conflict code
            parent = self.providers[changed].dirname(sync[changed].path)
            if any(e[changed].changed for e in self.state.lookup_path(changed, parent)):
                changes = [e for e in self.state.lookup_path(changed, parent) if e[changed].changed]
                # set mtime to forever ago
                changes[0][changed].changed = 1
                log.debug("parent modify %s should happen first %s", sync[changed].path, changes)
                sync.punt()
                return REQUEUE

        if sync[changed].exists == TRASHED:
            log.debug("delete")
            self.delete_synced(sync, changed, synced)
            return FINISHED

        if sync.is_path_change(changed) or sync.is_creation(changed):
            ret = self.handle_path_change_or_creation(sync, changed, synced)
            if ret == REQUEUE:
                log.debug("requeue, not handled")
                return ret

        if sync[changed].hash != sync[changed].sync_hash:
            if sync[changed].sync_hash is None:
                sync[changed].sync_path = None
                # creation must have failed
                log.warning("needs create: %s index: %s bc %s != %s", sync, synced, sync[changed].hash, sync[changed].sync_hash)
                return REQUEUE
            # not a new file, which means we must have last sync info

            if sync[synced].exists == TRASHED:
                log.debug("dont upload to trashed, zero out trashed side")
                # not an upload
                sync[synced].exists = UNKNOWN
                sync[synced].hash = None
                sync[synced].changed = 0
                sync[synced].path = None
                sync[synced].oid = None
                sync[synced].sync_path = None
                sync[synced].sync_hash = None
                sync[changed].sync_path = None
                sync[changed].sync_hash = None
                return REQUEUE
                
            log.debug("needs upload: %s index: %s bc %s != %s", sync, synced, sync[changed].hash, sync[changed].sync_hash)

            assert sync[synced].oid

            if not self.download_changed(changed, sync):
                return REQUEUE
            if not self.upload_synced(changed, sync):
                return REQUEUE
            return FINISHED

        log.debug("nothing changed %s", sync)
#        self.state.repair_index()
        return FINISHED

    def update_sync_path(self, sync, changed):
        assert sync[changed].oid

        info = self.providers[changed].info_oid(sync[changed].oid)
        if not info:
            sync[changed].exists = TRASHED
            return

        if not info.path:
            log.warning("impossible sync, no path. "
                        "Probably a file that was shared, but not placed into a folder. discarding. %s",
                        sync[changed])
            self.discard_entry(sync)
            return

        log.debug("UPDATE PATH %s->%s", sync, info.path)
        self.update_entry(
            sync, changed, sync[changed].oid, path=info.path, exists=True)

    def handle_hash_conflict(self, sync):
        log.debug("splitting hash conflict %s", sync)

        # split the sync in two
        defer_ent, defer_side, replace_ent, replace_side \
            = self.state.split(sync)
        return self.handle_split_conflict(
            defer_ent, defer_side, replace_ent, replace_side)

    def handle_split_conflict(self, defer_ent, defer_side, replace_ent, replace_side):
        if defer_ent[defer_side].otype == FILE:
            if not self.download_changed(defer_side, defer_ent):
                return False
            try:
                with open(defer_ent[defer_side].temp_file, "rb") as f:
                    dhash = self.providers[replace_side].hash_data(f)
                    if dhash == replace_ent[replace_side].hash:
                        log.debug("same hash as remote, discard entry")
                        self.discard_entry(replace_ent)
                        return True
            except FileNotFoundError:
                return False

        self.resolve_conflict((defer_ent[defer_side], replace_ent[replace_side]))
        return True

    def handle_path_conflict(self, sync):
        # consistent handling
        log.debug("handle path conflict %s", sync)

        path1 = sync[0].path
        path2 = sync[1].path
        if path1 > path2:
            pick = 0
        else:
            pick = 1
        picked = sync[pick]
        other = sync[other_side(pick)]
        other_path = self.translate(other.side, picked.path)
        if other_path is None:
            return

        other_info = self.providers[other.side].info_oid(other.oid)

        log.debug("renaming to handle path conflict: %s -> %s",
                  other.oid, other_path)

        def _update_syncs(new_oid):
            self.update_entry(sync, other.side, new_oid, path=other_path)
            if sync[other.side].sync_path:
                sync[other.side].sync_path = sync[other.side].path

            if sync[picked.side].sync_path:
                sync[picked.side].sync_path = sync[picked.side].path

        try:
            if other_info.path == other_path:
                # don't sync this entry
                log.warning("supposed rename conflict, but the names are the same")
                if not sync[other.side].sync_hash and sync[other.side].otype == FILE:
                    log.warning("sync_hashes missing even though the sync_path is set...")
                    sync[other.side].sync_path = None
                if not sync[picked.side].sync_hash and sync[picked.side].otype == FILE:
                    log.warning("sync_hashes missing even though the sync_path is set...")
                    sync[picked.side].sync_path = None
                raise CloudFileExistsError()
            new_oid = self.providers[other.side].rename(other.oid, other_path)
            _update_syncs(new_oid)
        except CloudFileExistsError:
            # other side already agrees
            _update_syncs(other.oid)

    def detect_parent_conflict(self, sync: SyncEntry, changed) -> Optional[str]:
        provider = self.providers[changed]
        path = sync[changed].sync_path
        parent = provider.dirname(path)
        while path != parent:
            ents = list(self.state.lookup_path(changed, parent))
            for ent in ents:
                ent: SyncEntry
                if ent[changed].changed:
                    return ent[changed].path
            path = parent
            parent = provider.dirname(path)
        return None
