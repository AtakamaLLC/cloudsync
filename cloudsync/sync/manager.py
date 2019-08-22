import os
import io
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

from .state import SyncState, SyncEntry, SideState, TRASHED, EXISTS, LOCAL, REMOTE
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
        ret = self.fh.read(*a)
        log.debug("RESOLVE FILE %s", ret)
        return ret

    def write(self, buf):
        return self.fh.write(buf)

    def close(self):
        return self.fh.close()

    def seek(self, *a):    
        return self.fh.seek(*a)

class SyncManager(Runnable):  # pylint: disable=too-many-public-methods
    def __init__(self, state, providers: Tuple[Provider, Provider], translate, resolve_conflict, sleep=0):
        self.state: SyncState = state
        self.providers: Tuple[Provider, Provider] = providers
        self.providers[LOCAL].debug_name = "local"
        self.providers[REMOTE].debug_name = "remote"
        self.translate = translate
        self.__resolve_conflict = resolve_conflict
        self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")

        self._sleep = sleep

        if sleep is None:
            sleep = 0

        assert len(self.providers) == 2

    def set_resolver(self, resolver):
        self.__resolve_conflict = resolver

    def do(self):
        sync: SyncEntry = self.state.change()
        if sync:
            try:
                self.sync(sync)
                self.state.storage_update(sync)
            except CloudTemporaryError as e:
                log.error(
                    "exception %s[%s] while processing %s, %i", type(e), e, sync, sync.punted)
                sync.punt()
            except Exception as e:
                log.exception(
                    "exception %s[%s] while processing %s, %i", type(e), e, sync, sync.punted, stack_info=True)
                sync.punt()
                time.sleep(self._sleep)
        else:
            if self._sleep:
                log.debug("SyncManager sleeping %i", self._sleep)
                time.sleep(self._sleep)

    def done(self):
        log.info("cleanup %s", self.tempdir)
        shutil.rmtree(self.tempdir)

    def get_latest_state(self, ent):
        log.debug("before update state %s", ent)
        for i in (LOCAL, REMOTE):
            if not ent[i].changed:
                continue

            info = self.providers[i].info_oid(ent[i].oid, use_cache=False)

            if not info:
                if ent[i].exists == EXISTS:
                    log.warning("File is believed to exist, but info not found, so setting it to trashed. %s", ent, stack_info=True)
                ent[i].exists = TRASHED
                continue

            ent[i].exists = EXISTS
            ent[i].hash = info.hash
            ent[i].otype = info.otype

            if ent[i].otype == FILE:
                if ent[i].hash is None:
                    ent[i].hash = self.providers[i].hash_oid(ent[i].oid)

                if ent[i].exists == EXISTS:
                    assert ent[i].hash is not None, "Cannot sync if hash is None"

            if ent[i].path != info.path:
                self.state.update_entry(ent, oid=ent[i].oid, side=i, path=info.path)

        log.debug("after update state %s", ent)

    def path_conflict(self, ent):
        if ent[0].path and ent[1].path:
            return not self.providers[0].paths_match(ent[0].path, ent[0].sync_path) and \
                   not self.providers[1].paths_match(ent[1].path, ent[1].sync_path)
        return False

    def sync(self, sync):
        self.get_latest_state(sync)

        if sync.hash_conflict():
            self.handle_hash_conflict(sync)
            return

        if self.path_conflict(sync):
            self.handle_path_conflict(sync)
            return

        for i in (LOCAL, REMOTE):
            if sync[i].changed:
                response = self.embrace_change(sync, i, other_side(i))
                if response == FINISHED:
                    self.finished(i, sync)
                break

        log.debug("table\r\n%s", self.state.pretty_print())

    def temp_file(self):
        # prefer big random name over NamedTemp which can infinite loop in odd situations!
        ret = os.path.join(self.tempdir, os.urandom(16).hex())
        log.debug("tempdir %s -> %s", self.tempdir, ret)
        return ret

    def finished(self, side, sync):
        sync[side].changed = None
        self.state.finished(sync)
        self.clean_temps(sync)

    @staticmethod
    def clean_temps(sync):
        #todo: move this to the sync obj
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
            log.debug("%s download %s to %s", self.providers[changed], sync[changed].oid, sync[changed].temp_file + ".tmp")
            with open(sync[changed].temp_file + ".tmp", "wb") as f:
                self.providers[changed].download(sync[changed].oid, f)
            os.rename(sync[changed].temp_file + ".tmp", sync[changed].temp_file)
            return True
        except PermissionError as e:
            raise CloudTemporaryError("download or rename exception %s" % e)

        except CloudFileNotFoundError:
            log.debug("download from %s failed fnf, switch to not exists",
                      self.providers[changed].debug_name)
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
                    ent.discard()
                    self.state.storage_update(ent)
        ents = [ent for ent in ents if not ent.discarded]
        ents = [ent for ent in ents if TRASHED not in (
            ent[changed].exists, ent[synced].exists)]

        if ents:
            if not sync.punted:
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
                    ent.discard()
                    self.state.storage_update(ent)
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
                      self.providers[synced].debug_name, translated_path, debug_sig(oid))

            # did i already have that oid? if so, chuck it
            already_dir = self.state.lookup_oid(synced, oid)
            if already_dir and already_dir != sync and already_dir[synced].otype == DIRECTORY:
                log.debug("discard %s", already_dir)
                already_dir.discard()

            sync[synced].sync_path = translated_path
            sync[changed].sync_path = sync[changed].path

            self.state.update_entry(
                sync, synced, exists=True, oid=oid, path=translated_path)

            return FINISHED
        except CloudFileNotFoundError:
            if not sync.punted:
                sync.punt()
                return REQUEUE
           
            log.debug("mkdir %s : %s failed fnf, TODO fix mkdir code and stuff",
                      self.providers[synced].debug_name, translated_path)
            raise NotImplementedError("TODO mkdir, and make state etc")

    def upload_synced(self, changed, sync):
        assert sync[changed].temp_file

        synced = other_side(changed)
        try:
            info = self.providers[synced].upload(
                sync[synced].oid, open(sync[changed].temp_file, "rb"))
            log.debug("upload to %s as path %s",
                      self.providers[synced].debug_name, sync[synced].sync_path)
            sync[synced].sync_hash = info.hash
            if info.path:
                sync[synced].sync_path = info.path
            else:
                sync[synced].sync_path = sync[synced].path
            sync[changed].sync_hash = sync[changed].hash
            sync[changed].sync_path = sync[changed].path

            self.state.update_entry(
                sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path)
        except CloudFileNotFoundError:
            log.debug("upload to %s failed fnf, TODO fix mkdir code and stuff",
                      self.providers[synced].debug_name)
            raise NotImplementedError("TODO mkdir, and make state etc")
        except CloudFileExistsError:
            # this happens if the remote oid is a folder
            log.debug("split bc upload to folder")

            defer_ent, defer_side, replace_ent, replace_side \
                = self.state.split(sync)

            self.handle_split_conflict(
                defer_ent, defer_side, replace_ent, replace_side)

    def _create_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        log.debug("create on %s as path %s",
                  self.providers[synced].debug_name, translated_path)
        try:
            info = self.providers[synced].create(
                translated_path, open(sync[changed].temp_file, "rb"))
            log.debug("created %s", info)
        except CloudFileExistsError:
            info = self.providers[synced].info_path(translated_path)
            if not info:
                raise
            with open(sync[changed].temp_file, "rb") as f:
                existing_hash = self.providers[synced].hash_data(f)
            if existing_hash != info.hash:
                raise
            log.debug("use existing %s", info)

        sync[synced].sync_hash = info.hash
        if info.path:
            sync[synced].sync_path = info.path
        else:
            sync[synced].sync_path = translated_path
        sync[changed].sync_hash = sync[changed].hash
        sync[changed].sync_path = sync[changed].path
        self.state.update_entry(
            sync, synced, exists=True, oid=info.oid, path=sync[synced].sync_path, hash=info.hash)

    def create_synced(self, changed, sync, translated_path):
        synced = other_side(changed)
        try:
            self._create_synced(changed, sync, translated_path)
            return FINISHED
        except CloudFileNotFoundError:
            log.debug("can't create %s, try mkdirs", translated_path)
            parent, _ = self.providers[synced].split(translated_path)
            self.providers[synced].mkdirs(parent)
            self._create_synced(changed, sync, translated_path)
            return FINISHED
        except CloudFileExistsError:
            # there's a file or folder in the way, let that resolve if possible
            log.debug("can't create %s, try punting", translated_path)

            if sync.punted > 0:
#                if self.resolve_conflict(sync[changed], sync[synced]):
#                    return FINISHED
                self.rename_to_fix_conflict(sync, changed, translated_path)
                sync.punt()
            else:
                sync.punt()
            return REQUEUE

    def resolve_conflict(self, ent1: SideState, ent2: SideState): # pylint: disable=no-self-use
        assert type(ent1) is SideState
        assert type(ent2) is SideState

        if not ent1.temp_file:
            ent1.temp_file = self.temp_file()

        if not ent2.temp_file:
            ent2.temp_file = self.temp_file()

        f1 = ResolveFile(ent1, self.providers[ent1.side])
        f2 = ResolveFile(ent2, self.providers[ent2.side])

        assert ent1.oid
        assert ent2.oid

        try:
            ret = self.__resolve_conflict(f1, f2)
        except Exception as e:
            log.exception("exception during conflict resolution %s", e)
            ret = None

        if ret is None:
            return False

        is_file_like = lambda f: hasattr(f, "read") and hasattr(f, "close")

        if not is_file_like(ret):
            log.error("bad return value for resolve conflict %s", ret)
            return False

        if ret is not f1:
            ret.seek(0)
            info1 = self.providers[other_side(ent2.side)].upload(ent1.oid, ret)
            ent1.hash = info1.hash
            ent1.sync_hash = info1.hash
            ent1.sync_path = info1.path

        if ret is not f2:
            ret.seek(0)
            info2 = self.providers[other_side(ent1.side)].upload(ent2.oid, ret)
            ent2.hash = info2.hash
            ent2.sync_hash = info2.hash
            ent2.sync_path = info2.path

        log.debug("RESOLVED CONFLICT: %s <-> %s", ent1, ent2)
        return True

    def delete_synced(self, sync, changed, synced):
        log.debug("try sync deleted %s", sync[changed].path)
        # see if there are other entries for the same path, but other ids
        ents = list(self.state.lookup_path(changed, sync[changed].path))
        ents = [ent for ent in ents if ent != sync]

        if not ents:
            if sync[synced].oid:
                try:
                    self.providers[synced].delete(sync[synced].oid)
                except CloudFileNotFoundError:
                    pass
            else:
                log.debug("was never synced, ignoring deletion")
            sync[synced].exists = TRASHED
            sync.discard()
        else:
            has_log = False
            for ent in ents:
                if ent.is_creation(changed):
                    log.debug("discard delete, pending create %s", sync)
                    has_log = True
            if not has_log:
                log.warning("conflict delete %s <-> %s", ents, sync)
            log.debug("discard %s", sync)
            sync.discard()

    def check_disjoint_create(self, sync, changed, synced, translated_path):
        # check for creation of a new file with another in the table

        if sync[changed].otype != FILE:
            return False

        ents = list(self.state.lookup_path(synced, translated_path))

        # filter for exists
        other_ents = [ent for ent in ents if ent != sync]
        if not other_ents:
            return False

        log.debug("found matching %s other ents %s",
                  translated_path, other_ents)

        # ignoring trashed entries with different oids on the same path
        if all(TRASHED in (ent[synced].exists, ent[changed].exists) for ent in other_ents):
            return False

        other_untrashed_ents = [ent for ent in other_ents if TRASHED not in (
            ent[synced].exists, ent[changed].exists)]

        assert len(other_untrashed_ents) == 1

        log.debug("split conflict found : %s", other_untrashed_ents)
        
        self.handle_split_conflict(
            other_untrashed_ents[0], synced, sync, changed)

        return True

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
                return REQUEUE

        if sync.is_creation(changed):
            assert not sync[changed].sync_hash
            # looks like a new file

            if sync[changed].otype == DIRECTORY:
                return self.mkdir_synced(changed, sync, translated_path)

            if not self.download_changed(changed, sync):
                return REQUEUE

            if sync[synced].oid:
                self.upload_synced(changed, sync)
            else:
                return self.create_synced(changed, sync, translated_path)
        else:  # handle rename
            if self.providers[synced].paths_match(sync[synced].sync_path, translated_path):
                return FINISHED

#            parent_conflict = self.detect_parent_conflict(sync, changed)
#            if parent_conflict:
#                log.info("can't rename %s->%s yet, do parent %s first. %s", sync[changed].sync_path, sync[changed].path, parent_conflict, sync)
#                sync.punt()
#                return REQUEUE

            log.debug("rename %s %s", sync[synced].sync_path, translated_path)
            try:
                new_oid = self.providers[synced].rename(sync[synced].oid, translated_path)
            except CloudFileNotFoundError:
                log.debug("ERROR: can't rename for now %s", sync)
                if sync.punted > 5:
                    log.exception("punted too many times, giving up")
                    return FINISHED
                else:
                    sync.punt()
                return REQUEUE
            except CloudFileExistsError:
                log.debug("can't rename, file exists")
                if sync.punted:
                    log.debug("rename for conflict")
                    self.rename_to_fix_conflict(sync, synced, translated_path)
                sync.punt()
                return REQUEUE

            sync[synced].sync_path = translated_path
            sync[changed].sync_path = sync[changed].path
            self.state.update_entry(sync, synced, path=translated_path, oid=new_oid)
            # TODO: update all the kids in a changed folder like so:
            # if sync[changed].otype == DIRECTORY:
            #     for ent in self.providers[changed].listdir(sync[changed].oid):
        return FINISHED

    def rename_to_fix_conflict(self, sync, side, path):
        old_oid, new_oid, new_name = self.conflict_rename(side, path)
        if new_name is None:
            return False

        log.debug("rename to fix conflict %s -> %s", sync[side].path, new_name)
        # file can get renamed back, if there's a cycle
        if old_oid == sync[side].oid:
            self.state.update_entry(sync, side=side, oid=new_oid)
        else:
            ent = self.state.lookup_oid(side, old_oid)
            if ent:
                self.state.update_entry(ent, side=side, oid=new_oid)

        return True

    def conflict_rename(self, side, path):

        index = path.find(".")
        if index >= 0:
            base = path[:index]
            ext = path[index:]
        else:
            base = path
            ext = ""

        conflict_name = base + ".conflicted" + ext

        oinfo = self.providers[side].info_path(path)

        if not oinfo:
            return None, None, None

        i = 1
        new_oid = None
        while new_oid is None:
            try:
                new_oid = self.providers[side].rename(oinfo.oid, conflict_name)
            except CloudFileExistsError:
                i = i + 1
                conflict_name = path + ".conflicted" + str(i)

        return oinfo.oid, new_oid, conflict_name

    def embrace_change(self, sync, changed, synced):
        log.debug("embrace %s", sync)

        if sync[changed].path:
            translated_path = self.translate(synced, sync[changed].path)
            if not translated_path:
                log.debug(">>>Not a cloud path %s", sync[changed].path)
                sync.discard()
                self.state.storage_update(sync)
                return FINISHED

        if sync[changed].exists == TRASHED:
            self.delete_synced(sync, changed, synced)
            return FINISHED

        if sync.is_path_change(changed) or sync.is_creation(changed):
            ret = self.handle_path_change_or_creation(sync, changed, synced)
            if ret == REQUEUE:
                return ret

        if sync[changed].hash != sync[changed].sync_hash:
            # not a new file, which means we must have last sync info

            log.debug("needs upload: %s index: %s", sync, synced)

            assert sync[synced].oid

            self.download_changed(changed, sync)
            self.upload_synced(changed, sync)
            return FINISHED

        log.info("nothing changed %s, but changed is true", sync)
        return FINISHED

    def update_sync_path(self, sync, changed):
        assert sync[changed].oid

        info = self.providers[changed].info_oid(sync[changed].oid)
        if not info:
            sync[changed].exists = TRASHED
            return

        if not info.path:
            log.warning("impossible sync, no path. "
                        "Probably a file that was shared, but not placed into a folder. Discarding. %s",
                        sync[changed])
            sync.discarded = True
            return

        log.debug("UPDATE PATH %s->%s", sync, info.path)
        self.state.update_entry(
            sync, changed, sync[changed].oid, path=info.path, exists=True)

    def handle_hash_conflict(self, sync):
        log.debug("splitting hash conflict %s", sync)

        # split the sync in two
        defer_ent, defer_side, replace_ent, replace_side \
            = self.state.split(sync)
        self.handle_split_conflict(
            defer_ent, defer_side, replace_ent, replace_side)

    def handle_split_conflict(self, defer_ent, defer_side, replace_ent, replace_side):
        if self.resolve_conflict(defer_ent[defer_side], replace_ent[replace_side]):
            self.state.update_entry(defer_ent, replace_side, replace_ent[replace_side].oid, path=replace_ent[replace_side].path, hash=replace_ent[replace_side].hash)
            defer_ent[defer_side].sync_hash = defer_ent[defer_side].hash
            defer_ent[defer_side].path = defer_ent[defer_side].path
            replace_ent.discard()
            return

        if defer_ent[defer_side].otype == FILE:
            self.download_changed(defer_side, defer_ent)
            with open(defer_ent[defer_side].temp_file, "rb") as f:
                dhash = self.providers[replace_side].hash_data(f)
                if dhash == replace_ent[replace_side].hash:
                    log.debug("same hash as remote, discard entry")
                    replace_ent.discard()
                    return

        self.rename_to_fix_conflict(replace_ent, replace_side, replace_ent[replace_side].path)

        log.debug("REPLACE %s", replace_ent)

        # force download of other side
        self.state.mark_changed(defer_side, defer_ent)

        defer_ent[defer_side].sync_path = None
        defer_ent[defer_side].sync_hash = None

        log.debug("SPLITTY\n%s", self.state.pretty_print())

    def handle_path_conflict(self, sync):
        # consistent handling
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
        log.debug("renaming to handle path conflict: %s -> %s",
                  other.oid, other_path)
        try:
            new_oid = self.providers[other.side].rename(other.oid, other_path)
            self.state.update_entry(sync, other.side, new_oid, path=other_path)
            sync[other.side].sync_path = sync[other.side].path
            sync[picked.side].sync_path = sync[picked.side].path
        except CloudFileExistsError:
            self.state.update_entry(sync, other.side, other.oid, path=other_path)
            sync[other.side].sync_path = sync[other.side].path
            sync[picked.side].sync_path = sync[picked.side].path
            # other side already agrees
            pass

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
