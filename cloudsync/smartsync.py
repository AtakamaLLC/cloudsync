from typing import Optional, Tuple, TYPE_CHECKING, Callable, List, Set
from cloudsync import CloudSync, SyncManager, SyncState, SyncEntry
from cloudsync.types import LOCAL, REMOTE, DIRECTORY, OInfo, DirInfo
from dataclasses import dataclass

if TYPE_CHECKING:  # pragma: no cover
    from .provider import Provider
    from cloudsync import Storage

class SmartSyncManager(SyncManager):
    """Class to allow for syncing files only on demand."""
    def pre_sync(self, sync: SyncEntry) -> bool:  # pylint: disable=too-many-branches
        finished = super().pre_sync(sync)
        if not finished:
            finished = not (sync in self.state.requestset or sync[REMOTE].otype == DIRECTORY)
        return finished

    def _get_parent_conflicts(self, sync: SyncEntry, changed) -> List[SyncEntry]:
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
        super().__init__(providers, storage, tag, shuffle, prioritize)

    def smart_sync_ent(self, ent):
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
            self.smart_sync_ent(ent)
        return ents

    def smart_sync_oid(self, remote_oid) -> SyncEntry:
        ent = self.lookup_oid(REMOTE, remote_oid)
        self.smart_sync_ent(ent)
        return ent

    def _smart_unsync_ent(self, ent):
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

    def smart_unsync_path(self, remote_path) -> Optional[SyncEntry]:
        ents = self.lookup_path(REMOTE, remote_path)
        return self._smart_unsync(ents, remote_path)

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
        folders = [ent for ent in self._changeset_storage if ent[REMOTE].otype == DIRECTORY or 
                   (ent[REMOTE].changed and ent[REMOTE].changed > ent[REMOTE]._last_gotten)]  # pylint: disable=protected-access
        retval = self.requestset.intersection(self._changeset_storage).union(folders).difference(self.excludeset)
        return retval

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
        self._callbacks: List[callable] = list()
        super().__init__(providers=providers, roots=roots, storage=storage,
                         sleep=sleep, root_oids=root_oids, smgr_class=SmartSyncManager, state_class=SmartSyncState)

    def _ent_to_smartinfo(self, ent: SyncEntry, local_dir_info: Optional[DirInfo]) -> SmartInfo:
        _ignored_remote_ent_parent, remote_ent_name = self.providers[REMOTE].split(ent[REMOTE].path)
        local_path = self.translate(LOCAL, ent[REMOTE].path)
        if not local_dir_info:
            local_dir_info = self.providers[LOCAL].info_path(local_path)
        if local_dir_info and ent[LOCAL].oid == local_dir_info.oid:  # file is synced, use the local info
            otype = local_dir_info.otype
            oid = local_dir_info.oid
            remote_oid = ent[REMOTE].oid
            hash = local_dir_info.hash
            path = local_dir_info.path or ent[LOCAL].path
            size = local_dir_info.size
            name = local_dir_info.name or remote_ent_name
            mtime = local_dir_info.mtime
            is_synced = True
        else:
            otype = ent[REMOTE].otype
            oid = ent[LOCAL].oid
            remote_oid = ent[REMOTE].oid
            hash = None
            path = local_path
            size = ent[REMOTE].size
            name = remote_ent_name
            mtime = ent[REMOTE].mtime
            is_synced = False
        shared = False  # TODO: ent[REMOTE].shared,
        readonly = False  # TODO: ent[REMOTE].readonly
        retval = SmartInfo(otype=otype,
                           oid=oid,
                           remote_oid=remote_oid,
                           hash=hash,
                           path=path,
                           size=size,
                           name=name,
                           mtime=mtime,
                           shared=shared,  # TODO: ent[REMOTE].shared,
                           readonly=readonly,  # TODO: ent[REMOTE].readonly
                           is_synced=is_synced,
                           )
        return retval

    def _smart_unsync_ent(self, ent):
        if ent[LOCAL].sync_path:
            ent_info = self.providers[LOCAL].info_path(ent[LOCAL].path)
            if ent_info:
                self.providers[LOCAL].delete(ent_info.oid)

    def smart_unsync_oid(self, remote_oid):
        ent = self.state.smart_unsync_oid(remote_oid)
        if ent:
            self._smart_unsync_ent(ent)

    def smart_unsync_path(self, path, side):
        path = self._ensure_path_remote(path, side)
        ent = self.state.smart_unsync_path(path)
        if ent:
            self._smart_unsync_ent(ent)

    def _smart_sync_ent(self, ent: SyncEntry) -> bool:
        """Request to sync down a file from the cloud, and mark the entry to maintain synchronization."""
        # if the local file is missing,
        #   clear the local side of the ent and
        #   mark the remote side changed and clear the sync_path/sync_hash so that it will look new and sync down
        #   this should override the local deletion event from before
        # TODO: is there a race condition based on the local deletion event coming later? This might wrongly delete!
        for parent_conflict in self.smgr._get_parent_conflicts(ent, REMOTE):  # ALWAYS remote
            self.smgr._sync_one_entry(parent_conflict)
        return self.smgr._sync_one_entry(ent)

    def smart_sync_oid(self, remote_oid):
        ent = self.state.smart_sync_oid(remote_oid)
        if not ent:
            raise FileNotFoundError(remote_oid)
        self._smart_sync_ent(ent)

    def smart_sync_path(self, path, side):
        remote_path = self._ensure_path_remote(path, side)
        ents = self.state.smart_sync_path(remote_path)
        if not ents:
            raise FileNotFoundError(remote_path)
        for ent in ents:
            self._smart_sync_ent(ent)

    def smart_listdir_path(self, local_path):
        # assumes that local is efficient and remote is inefficient
        # read from cache as much as possible remotely, read from disk as much as possible locally
        # calls local listdir, local listdir overrides cached info, and also update the state with this info too
        #   remote_oid and is_synced
        remote_path = self.translate(REMOTE, local_path)
        dirents = dict()
        for dirent in self.providers[LOCAL].listdir_path(local_path):
            dirents[dirent.oid] = dirent
        for ent in self.state.smart_listdir_path(remote_path):
            yield self._ent_to_smartinfo(ent, dirents.get(ent[LOCAL].oid))

    def _ensure_path_remote(self, path, side) -> str:
        if side == LOCAL:
            path = self.translate(REMOTE, path)  # TODO translate the path to remote
        return path

    def register_auto_sync_callback(self, callback):
        self._callbacks.append(callback)

    def smart_info_path(self, local_path) -> Optional[SmartInfo]:
        remote_path = self.translate(REMOTE, local_path)
        ents = self.state.lookup_path(REMOTE, remote_path)
        if ents:
            return self._ent_to_smartinfo(ents[0], None)
        return None

    def smart_info_oid(self, remote_oid) -> Optional[SmartInfo]:
        ent = self.state.lookup_oid(REMOTE, remote_oid)
        if ent:
            return self._ent_to_smartinfo(ent, None)
        return None
