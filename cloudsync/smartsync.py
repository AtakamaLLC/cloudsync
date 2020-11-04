import time
import logging
import tempfile
from threading import RLock
from dataclasses import dataclass
from typing import Optional, Tuple, TYPE_CHECKING, Callable, List, Set
from cloudsync import CloudSync, SyncManager, SyncState, SyncEntry
from cloudsync.types import LOCAL, REMOTE, DIRECTORY, OInfo, DirInfo
log = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover
    from .provider import Provider
    from cloudsync import Storage
    from cloudsync.notification import NotificationManager


class SmartSyncManager(SyncManager):   # pylint: disable=too-many-instance-attributes
    """Class to allow for syncing files only on demand."""
    # TODO: this is a copy of the init from SyncState, which should be unified
    #   The problem is that mypy doesn't like the fact that the type of the 'state' parament is not correct in super()
    #   perhaps remove the state paramater from the init, and create a method 'set_state' that sets the state
    #   and then that can be overridden in the subclass and the types will work out, but this will mean
    #   refactoring any of the clients of the SyncManager to use it
    def __init__(self, state: 'SmartSyncState',                        # pylint: disable=too-many-arguments, super-init-not-called
                 providers: Tuple['Provider', 'Provider'],
                 translate: Callable,
                 resolve_conflict: Callable,
                 notification_manager: Optional['NotificationManager'] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_paths: Optional[Tuple[str, str]] = None,
                 root_oids: Optional[Tuple[str, str]] = None):
        self.state = state
        self.providers: Tuple['Provider', 'Provider'] = providers
        self.__translate = translate
        self.translate = lambda side, path: self.__translate(side, path) if path else None
        self._resolve_conflict = resolve_conflict
        self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")
        self.__nmgr = notification_manager
        self._root_oids: List[str] = list(root_oids) if root_oids else [None, None]
        self._root_paths: List[str] = list(root_paths) if root_paths else [None, None]
        if not sleep:
            # these are the event sleeps, but really we need more info than this
            sleep = (self.providers[LOCAL].default_sleep, self.providers[REMOTE].default_sleep)

        self.sleep = sleep

        ####

        max_sleep = max(sleep)                    # on sync fail, use the worst time for backoff
        self.aging = max_sleep / 5                # how long before even trying to sync
        self.min_backoff = max_sleep / 10.0       # event sleep of 15 seconds == 1.5 second backoff on failures
        self.max_backoff = max_sleep * 10.0       # escalating up to a 3 minute wait time
        self.mult_backoff = 2
        assert len(self.providers) == 2
    def pre_sync(self, sync: SyncEntry) -> bool:  # pylint: disable=too-many-branches
        finished = super().pre_sync(sync)
        local_file = sync[LOCAL].oid and self.providers[LOCAL].exists_oid(sync[LOCAL].oid)
        if not finished:
            finished = not (local_file or sync in self.state.requestset or sync[REMOTE].otype == DIRECTORY)
        return finished

    def get_parent_conflicts(self, sync: SyncEntry, changed) -> List[SyncEntry]:
        """Returns list of parent conflicts."""
        done = False
        pcs = []
        new_pc = sync
        while not done:
            pc = self._get_parent_conflict(new_pc, changed)
            # if pc:  # TODO: test if this is necessary
            #     pc.get_latest()
            if pc and pc[REMOTE].path != new_pc[REMOTE].path:
                pcs.append(pc)
                new_pc = pc
            else:
                done = True
        pcs.reverse()
        return pcs


class SmartSyncState(SyncState):
    """Enhances the syncstate to support smart syncing."""
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 storage: Optional['Storage'] = None,
                 tag: Optional[str] = None,
                 shuffle: bool = False,
                 prioritize: Callable[[int, str], int] = None):
        self.requestset: Set[SyncEntry] = set()
        self.excludeset: Set[SyncEntry] = set()
        self._callbacks: List[Callable] = list()
        super().__init__(providers, storage, tag, shuffle, prioritize)

    def register_auto_sync_callback(self, callback):
        self._callbacks.append(callback)

    def _smart_sync_ent(self, ent):
        if ent[LOCAL].path and not self.providers[LOCAL].exists_path(ent[LOCAL].path):
            ent[LOCAL].clear()
            ent[REMOTE].sync_path = None
            ent[REMOTE].sync_hash = None
            self.update_entry(ent, REMOTE, None, changed=True)
        self.requestset.add(ent)
        self.excludeset.discard(ent)

    def smart_sync_path(self, remote_path) -> List[SyncEntry]:
        # q: do we want to raise an exception if path isn't found?
        # q: do we need to also sync path's parents all the way to the root?
        #   a: probably, but it doesn't make sense to add them to the requestset, just sync them implicitly
        #       or maybe it does make sense to add them to the requestset? that way they will get subscribed too
        #       or maybe always sync all folders at all times, and only files are smartsynced
        ents = self.lookup_path(REMOTE, remote_path)
        for ent in ents:
            self._smart_sync_ent(ent)
        return ents

    def smart_sync_oid(self, remote_oid) -> SyncEntry:
        ent = self.lookup_oid(REMOTE, remote_oid)
        self._smart_sync_ent(ent)
        return ent

    def _smart_unsync_ent(self, ent):
        if ent[LOCAL].path:
            ent_info = self.providers[LOCAL].info_path(ent[LOCAL].path)
            if ent_info:
                self.providers[LOCAL].delete(ent_info.oid)
            ent[LOCAL].clear()
            ent[REMOTE].sync_path = None
            ent[REMOTE].sync_hash = None
        self.requestset.discard(ent)
        self.excludeset.add(ent)

    def _smart_unsync(self, ents, source_id) -> Optional[SyncEntry]:
        if not ents:
            raise FileNotFoundError(source_id)
        for ent in ents:
            if ent in self.requestset:
                self._smart_unsync_ent(ent)
                return ent
        return None

    def smart_unsync_ent(self, ent) -> Optional[SyncEntry]:
        return self._smart_unsync([ent], ent)

    def smart_unsync_oid(self, remote_oid) -> Optional[SyncEntry]:
        ent = self.lookup_oid(REMOTE, remote_oid)
        return self._smart_unsync([ent], remote_oid)

    def smart_listdir_path(self, remote_path):
        """returns the ents for all files in remote folder by looking in the state db, doesn't hit the provider api."""
        # TODO exclude files that are marked deleted but unsynced
        r_prov = self.providers[REMOTE]
        for ent, _ignored_rel_path in self.get_kids(remote_path, REMOTE):
            if r_prov.paths_match(r_prov.dirname(ent[REMOTE].path), remote_path):
                yield ent

    @property
    def changes(self):
        # Filter the changes to just those that are in the requestset, or those whose get_latest is stale viz. change_time
        changes = [ent[LOCAL].path for ent in super().changes]
        for ent in self.requestset:
            if ent[LOCAL].path in changes:
                yield ent

    @property
    def _changeset(self):
        # this implies a remote walk on startup, otherwise autosynced items won't autosync until an event shows up
        # do we want to do the autosync calculation on every do()? Or perhaps flag each entry that the
        #     autosync calculation has been done, and no need to do it again... if so, don't persist that flag
        changes = set()
        for ent in self._changeset_storage:
            if ent in self.excludeset and not ent[LOCAL].changed:
                continue

            included = False
            if ent in self.requestset:
                included = True
            elif ent[REMOTE].otype == DIRECTORY:
                included = True  # simplifies syncing files, avoids needing to sync the parent(s) later
            elif (ent[REMOTE].changed or ent[LOCAL].changed) and not ent.is_latest():
                included = True  # needs a get_latest() at least
            elif not ent[LOCAL].oid:  # this means the entry is not currently synced locally
                for callback in self._callbacks:
                    if callback(ent[REMOTE].path):
                        self._smart_sync_ent(ent)
                        included = True
                        break

            if included:
                changes.add(ent)

        return changes

    @_changeset.setter
    def _changeset(self, value):
        super()._changeset = value


@dataclass
class SmartInfo(OInfo):
    remote_oid: str = ''
    is_synced: bool = False


class SmartCloudSync(CloudSync):
    """Class to add smart sync functionality to the CloudSync class"""
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 roots: Optional[Tuple[str, str]] = None,
                 storage: Optional['Storage'] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_oids: Optional[Tuple[str, str]] = None
                 ):
        self._mutex = RLock()
        super().__init__(providers=providers, roots=roots, storage=storage,
                         sleep=sleep, root_oids=root_oids, smgr_class=SmartSyncManager, state_class=SmartSyncState)

    def do(self):
        time.sleep(.01)  # give smartsync a chance to preempt
        with self._mutex:
            super().do()

    def register_auto_sync_callback(self, callback):
        self.state.register_auto_sync_callback(callback)

    def _ent_to_smartinfo(self, ent: Optional[SyncEntry], local_dir_info: Optional[DirInfo], local_path) -> SmartInfo:  # pylint: disable=too-many-locals
        assert ent or local_dir_info, "must provide one of ent or local_dir_info"

        if local_dir_info:  # file is synced, use the local info
            otype = local_dir_info.otype
            oid = local_dir_info.oid
            remote_oid = ent[REMOTE].oid if ent else None
            obj_hash = local_dir_info.hash
            path = local_dir_info.path or ent[LOCAL].path
            size = local_dir_info.size
            name = local_dir_info.name
            mtime = local_dir_info.mtime
            is_synced = True
        else:
            otype = ent[REMOTE].otype
            oid = ent[LOCAL].oid
            remote_oid = ent[REMOTE].oid
            obj_hash = None
            path = local_path
            size = ent[REMOTE].size
            name = self.providers[REMOTE].basename(ent[REMOTE].path)
            mtime = ent[REMOTE].mtime
            is_synced = False
        shared = False  # TODO: ent[REMOTE].shared,
        readonly = False  # TODO: ent[REMOTE].readonly
        retval = SmartInfo(otype=otype,
                           oid=oid,
                           remote_oid=remote_oid,
                           hash=obj_hash,
                           path=path,
                           size=size,
                           name=name,
                           mtime=mtime,
                           shared=shared,  # TODO: ent[REMOTE].shared,
                           readonly=readonly,  # TODO: ent[REMOTE].readonly
                           is_synced=is_synced,
                           )
        return retval

    def _sync_one_entry(self, sync: SyncEntry):
        something_got_done = self.smgr.pre_sync(sync)
        if not something_got_done:
            something_got_done = self.smgr.sync(sync)
        self.state.storage_commit()
        return something_got_done

    def _smart_unsync_ent(self, ent):
        if ent:
            self.state.unconditionally_get_latest(ent, LOCAL)
            if ent[LOCAL].hash != ent[LOCAL].sync_hash or ent[LOCAL].parent.paths_differ(LOCAL):
                ent[LOCAL].changed = ent[LOCAL].changed or time.time()
                self._sync_one_entry(ent)

            found = self.state.smart_unsync_ent(ent)
            if found:
                self._smart_unsync_ent(found)
                return found
        return None


    def smart_unsync_oid(self, remote_oid):
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        self._smart_unsync_ent(ent)

    def smart_unsync_path(self, path, side):
        """Delete a file locally, but leave it in the cloud"""
        path = self._ensure_path_remote(path, side)
        state_ents = self.state.lookup_path(REMOTE, path)
        ents: set = self.state.requestset.intersection(state_ents)
        if not ents:
            return None
        found_ents = set()
        for ent in ents:
            found = self._smart_unsync_ent(ent)
            if found:
                found_ents.add(found)
        return found_ents

    def _smart_sync_ent(self, ent: SyncEntry) -> bool:
        """Request to sync down a file from the cloud, and mark the entry to maintain synchronization."""
        # if the local file is missing,
        #   clear the local side of the ent and
        #   mark the remote side changed and clear the sync_path/sync_hash so that it will look new and sync down
        with self._mutex:
            for parent_conflict in self.smgr.get_parent_conflicts(ent, REMOTE):  # ALWAYS remote
                self._sync_one_entry(parent_conflict)
            return self._sync_one_entry(ent)

    def smart_sync_oid(self, remote_oid):
        ent: SyncEntry = self.state.smart_sync_oid(remote_oid)
        if not ent:
            raise FileNotFoundError(remote_oid)
        self._smart_sync_ent(ent)
        return ent[LOCAL].path

    def smart_sync_path(self, path, side):
        remote_path = self._ensure_path_remote(path, side)
        ents = self.state.smart_sync_path(remote_path)
        if not ents:
            raise FileNotFoundError(remote_path)
        for ent in ents:
            self._smart_sync_ent(ent)

    def smart_listdir_path(self, local_path):
        """
        Returns the listdir calculated by the local listdir mixed with the remote sync state, when a file does
        not exist locally
        """
        # assumes that local is efficient and remote is inefficient
        # read from cache as much as possible remotely, read from disk as much as possible locally
        # calls local listdir, local listdir overrides cached info, and also update the state with this info too
        #   remote_oid and is_synced
        local, remote = self.providers
        remote_path = self.translate(REMOTE, local_path)
        local_ents = dict()
        remote_ents = dict()
        for dirent in local.listdir_path(local_path):
            local_ents[dirent.name] = dirent
        for ent in self.state.smart_listdir_path(remote_path):
            remote_ents[remote.basename(ent[REMOTE].path)] = ent
        names = set(local_ents.keys()).union(remote_ents.keys())
        for name in names:
            rent = remote_ents.get(name)
            lent = local_ents.get(name)
            yield_val = self._ent_to_smartinfo(rent, lent, local.join(local_path, name))
            yield yield_val

    def _ensure_path_remote(self, path, side) -> str:
        if side == LOCAL:
            path = self.translate(REMOTE, path)  # TODO translate the path to remote
        return path

    def smart_info_path(self, local_path) -> Optional[SmartInfo]:
        remote_path = self.translate(REMOTE, local_path)
        ents = self.state.lookup_path(REMOTE, remote_path)
        if ents:
            return self._ent_to_smartinfo(ents[0], None, local_path)
        return None

    def smart_info_oid(self, remote_oid) -> Optional[SmartInfo]:
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        if ent:
            local_path = self.translate(LOCAL, ent[REMOTE].path)
            return self._ent_to_smartinfo(ent, None, local_path)
        return None

    def smart_delete_oid(self, remote_oid):
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        self._smart_unsync_ent(ent)
        self.providers[REMOTE].delete(remote_oid)
