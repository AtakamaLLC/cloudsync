from typing import Optional, Tuple, TYPE_CHECKING, Callable, List
from cloudsync import CloudSync, SyncManager, SyncState, SyncEntry
from cloudsync.types import LOCAL, REMOTE, DIRECTORY, DirInfo

if TYPE_CHECKING:
    from .provider import Provider
    from cloudsync import Storage
    

class SmartSyncManager(SyncManager):
    """Class to allow for syncing files only on demand."""
    @property
    def changeset_len(self):
        return self.state.changeset_len

    @property
    def changes(self):
        return super().changes

    def pre_sync(self, sync: SyncEntry) -> bool:  # pylint: disable=too-many-branches
        finished = super().pre_sync(sync)
        if not finished:
            finished = not (sync in self.state.requestset or sync[REMOTE].otype == DIRECTORY)
        return finished

    def get_parent_conflicts(self, sync: SyncEntry, changed) -> List[SyncEntry]:
        """Returns list of parent conflicts."""
        done = False
        pcs = []
        new_pc = sync
        while not done:
            pc = self._get_parent_conflict(new_pc, changed)
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
        self.requestset = set()
        self.excludeset = set()
        super().__init__(providers, storage, tag, shuffle, prioritize)

    def smart_sync_ent(self, ent):
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
            self.requestset.add(ent)
        return ents

    def smart_unsync_ent(self, ent):
        self.requestset.discard(ent)
        self.excludeset.add(ent)

    def smart_unsync_path(self, remote_path):
        for ent in tuple(self.requestset):
            if ent[REMOTE].path == remote_path:
                self.state.smart_unsync_ent(ent)
                break

    def smart_listdir(self, local_path, remote_path):
        """Lists all files in a remote folder by looking in the state db, and doesn't hit the provider api."""
        prov = self.providers[REMOTE]
        for ent, _ignored_rel_path in self.get_kids(remote_path, REMOTE):
            remote_ent_path = ent[REMOTE].path
            _ignored_remote_ent_parent, remote_ent_name = self.providers[REMOTE].split(ent[REMOTE].path)
            if prov.paths_match(prov.dirname(remote_ent_path), remote_path):
                ent_info = prov.info_oid(ent[REMOTE].oid)
                retval = DirInfo(otype=ent[REMOTE].otype,
                                 oid='',
                                 hash=None,
                                 path=self.providers[LOCAL].join(local_path, remote_ent_name),
                                 size=ent_info.size,  # TODO: ent[REMOTE].size,
                                 name=remote_ent_name,
                                 mtime=0,  # TODO: ent[REMOTE].mtime,
                                 shared=False,  # TODO: ent[REMOTE].shared,
                                 readonly=False,  # TODO: ent[REMOTE].readonly
                                 )
                yield retval  # TODO: this needs to yield DirInfo, also translate back to local

    @property
    def changes(self):
        # Filter the changes to just those that are in the requestset, or those whose get_latest is stale viz. change_time
        changes = super().changes
        for ent in self.requestset:
            if ent[LOCAL].path in changes:
                yield ent

    @property
    def _changeset(self):
        folders = [ent for ent in self._changeset_storage if ent[REMOTE].otype == DIRECTORY or 
                   ent[REMOTE].changed > ent[REMOTE]._last_gotten]  # pylint: disable=protected-access
        retval = self.requestset.intersection(self._changeset_storage).union(folders).difference(self.excludeset)
        return retval

    # def change(self, age):
    #     super().change(age)
    #     requested_changes = self.requestset.intersection(self._changeset):
    #     if requested_changes:

    # def unconditionally_get_latest(self, ent, i):
    #     # TODO: get enhanced data (mtime, size, etc)
    #     super().unconditionally_get_latest(ent, i)


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
                         sleep=sleep, root_oids=root_oids, smgr_class=SmartSyncManager, state_class=SmartSyncState)

    def smart_unsync_ent(self, ent: SyncEntry):
        # remove ent from requestset
        # delete file, if it exists at path
        self.state.smart_unsync_ent(ent)
        if ent[LOCAL].sync_path:
            ent_info = self.providers[LOCAL].info_path(ent[LOCAL].path)
            if ent_info:
                self.providers[LOCAL].delete(ent_info.oid)

    def smart_unsync_path(self, path, side):
        # TODO: should this take an oid? we may not have a local oid, so it might have to be a remote oid always...
        path = self._make_path_remote(path, side)
        ents = self.state.lookup_path(REMOTE, path)
        if not ents:
            raise FileNotFoundError(path)
        for ent in ents:
            self.smart_unsync_ent(ent)

    def smart_sync_ent(self, ent):
        """Request to sync down a file from the cloud, and mark the entry to maintain synchronization."""
        # if the local file is missing,
        #   clear the local side of the ent and
        #   mark the remote side changed and clear the sync_path/sync_hash so that it will look new and sync down
        #   this should override the local deletion event from before
        # TODO: is there a race condition based on the local deletion event coming later? This might wrongly delete!
        if ent[LOCAL].path and not self.providers[LOCAL].exists_path(ent[LOCAL].path):
            ent[LOCAL].clear()
            ent[REMOTE].sync_path = None
            ent[REMOTE].sync_hash = None
            self.state.update_entry(ent, REMOTE, None, changed=True)
        self.state.smart_sync_ent(ent)
        for parent_conflict in self.smgr.get_parent_conflicts(ent, REMOTE):  # ALWAYS remote
            self.smgr.sync_one_entry(parent_conflict)
        self.smgr.sync_one_entry(ent)

    def smart_sync_path(self, path, side):
        # TODO: should this take an oid? we don't have a local oid, so it would have to be a remote oid always...
        path = self._make_path_remote(path, side)
        ents = self.state.lookup_path(REMOTE, path)
        if not ents:
            raise FileNotFoundError(path)
        for ent in ents:
            self.smart_sync_ent(ent)

    def smart_listdir_path(self, local_path):
        # TODO: should this take an oid? we don't have a local oid, so it would have to be a remote oid always...
        remote_path = self._make_path_remote(local_path, LOCAL)
        listdir = self.state.smart_listdir(local_path, remote_path)
        return listdir

    def _make_path_remote(self, path, side):
        if side == LOCAL:
            path = self.translate(REMOTE, path)  # TODO translate the path to remote
        return path


