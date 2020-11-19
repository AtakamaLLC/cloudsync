import time
import logging
from threading import RLock
from dataclasses import dataclass
from typing import Optional, Tuple, TYPE_CHECKING, Callable, List, Set, cast
from cloudsync import CloudSync, SyncManager, SyncState, SyncEntry, EventManager, Event
from cloudsync.types import LOCAL, REMOTE, DIRECTORY, OInfo, DirInfo
import cloudsync.exceptions as ex
from cloudsync.notification import SourceEnum
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
        super().__init__(cast(SyncState, state), providers, translate, resolve_conflict, notification_manager, sleep, root_paths, root_oids)
        self.state: SmartSyncState = state

    def do(self):
        time.sleep(.01)  # give smartsync a chance to preempt
        super().do()

    def pre_sync(self, sync: SyncEntry) -> bool:
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
        # We are automatically syncing all folders, so we don't need to worry about parent folders existing
        #   although this could be a concern before the initial sync with a bed is complete,
        #   parent_conflict handling should take care of it
        ents = self.lookup_path(REMOTE, remote_path)
        if not ents:
            raise ex.CloudFileNotFoundError(remote_path)
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
            raise ex.CloudFileNotFoundError(source_id)
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

    def smart_listdir_path(self, side, path):
        """returns the ents for all files in remote folder by looking in the state db, doesn't hit the provider api."""
        # TODO exclude files that are marked deleted but unsynced
        r_prov = self.providers[side]
        for ent, _ignored_rel_path in self.get_kids(path, side):
            if r_prov.paths_match(r_prov.dirname(ent[side].path), path):
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
                    if ent[REMOTE].path and callback(ent[REMOTE].path):
                        self._smart_sync_ent(ent)
                        included = True
                        break

            if included:
                changes.add(ent)

        return changes

    @_changeset.setter
    def _changeset(self, value):
        self._changeset_storage = value


@dataclass
class SmartInfo(OInfo):
    remote_oid: str = ''
    is_synced: bool = False


class SmartEventManager(EventManager):
    def _fill_event_path(self, event: Event):
        if event.path:
            return
        if event.prior_oid:
            log.error("rename from oid_is_path %s without full path", self.provider.name)   # pragma: no cover
        state = self.state.lookup_oid(self.side, event.oid)
        if state:
            if self.side == 1 or (state[self.side].path and self.provider.exists_path(state[self.side].path)):
                event.path = state[self.side].path
        # if there is no state entry, then the item is new, so make the event accurate
        #   so that the new state entry will have a size and mtime
        if not state or (not event.path and event.exists in (True, None)):
            self._make_event_accurate(event)


class SmartCloudSync(CloudSync):
    """Class to add smart sync functionality to the CloudSync class"""
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 roots: Optional[Tuple[str, str]] = None,
                 storage: Optional['Storage'] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_oids: Optional[Tuple[str, str]] = None
                 ):
        super().__init__(providers=providers, roots=roots, storage=storage,
                         sleep=sleep, root_oids=root_oids, smgr_class=SmartSyncManager,
                         emgr_class=SmartEventManager, state_class=SmartSyncState)

    def register_auto_sync_callback(self, callback: Callable):
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
        try:
            something_got_done = self.smgr.pre_sync(sync)
            if not something_got_done:
                something_got_done = self.smgr.sync(sync, want_raise=True)
            self.state.storage_commit()
            return something_got_done
        except ex.CloudException as e:
            path = sync[REMOTE].path if sync[REMOTE].path else sync[LOCAL].path
            self.nmgr.notify_from_exception(SourceEnum.SYNC, e, path)
            raise

    def _smart_unsync_ent(self, ent):
        if ent:
            self.state.unconditionally_get_latest(ent, LOCAL)
            if ent[LOCAL].hash != ent[LOCAL].sync_hash or ent[LOCAL].parent.paths_differ(LOCAL):
                ent[LOCAL].changed = ent[LOCAL].changed or time.time()
                self._sync_one_entry(ent)

            return self.state.smart_unsync_ent(ent)
        return None

    def smart_unsync_oid(self, remote_oid):
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        self._smart_unsync_ent(ent)

    def smart_unsync_path(self, path, side):
        """Delete a file locally, but leave it in the cloud"""
        remote_path = self._ensure_path_remote(path, side)
        if not remote_path:
            return None
        state_ents = self.state.lookup_path(REMOTE, remote_path)
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
        with self.state.lock:
            for parent_conflict in self.smgr.get_parent_conflicts(ent, REMOTE):  # ALWAYS remote
                self._sync_one_entry(parent_conflict)
            ent[REMOTE].mark_changed()
            return self._sync_one_entry(ent)

    def smart_sync_oid(self, remote_oid):
        ent: SyncEntry = self.state.smart_sync_oid(remote_oid)
        if not ent:
            raise ex.CloudFileNotFoundError(remote_oid)
        self._smart_sync_ent(ent)
        return ent[LOCAL].path

    def smart_sync_path(self, path, side):
        remote_path = self._ensure_path_remote(path, side)
        try:
            ents = self.state.smart_sync_path(remote_path)
        except ex.CloudException as e:
            self.nmgr.notify_from_exception(SourceEnum.SYNC, e, remote_path)
            raise
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
        local_dir_ents = dict()
        remote_ents = dict()
        for dirent in local.listdir_path(local_path):
            local_dir_ents[dirent.name] = dirent
        if remote_path:
            for ent in self.state.smart_listdir_path(REMOTE, remote_path):
                if self.translate(LOCAL, ent[REMOTE].path):
                    remote_ents[remote.basename(ent[REMOTE].path)] = ent
        names = set(local_dir_ents.keys()).union(remote_ents.keys())
        for name in names:
            rent = remote_ents.get(name)
            lent = local_dir_ents.get(name)
            if not rent or not rent[LOCAL].path or local.paths_match(self.translate(LOCAL, rent[REMOTE].path), rent[LOCAL].path):
                yield_val = self._ent_to_smartinfo(rent, lent, local.join(local_path, name))
                if yield_val.mtime or yield_val.size:
                    yield yield_val

    def _ensure_path_remote(self, path, side) -> str:
        if side == LOCAL:
            path = self.translate(REMOTE, path)  # TODO translate the path to remote
        return path

    def smart_info_path(self, local_path) -> Optional[SmartInfo]:
        remote_path = self.translate(REMOTE, local_path)
        if remote_path:
            ents = self.state.lookup_path(REMOTE, remote_path)
            if ents:
                return self._ent_to_smartinfo(ents[0], None, local_path)
        return None

    def smart_info_oid(self, remote_oid) -> Optional[SmartInfo]:
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        if ent:
            local_path = self.translate(LOCAL, ent[REMOTE].path)
            if local_path:
                return self._ent_to_smartinfo(ent, None, local_path)
        return None

    def smart_delete_oid(self, remote_oid):
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        self._smart_unsync_ent(ent)
        self.providers[REMOTE].delete(remote_oid)
