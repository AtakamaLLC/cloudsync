from cloudsync import CloudSync, SyncManager, SyncState, SyncEntry
from cloudsync.types import LOCAL, REMOTE, DIRECTORY
from typing import Optional, Tuple, TYPE_CHECKING, Callable, List

if TYPE_CHECKING:
    from .provider import Provider
    from cloudsync import Storage
    

class SmartSyncManager(SyncManager):
    @property
    def changeset_len(self):
        return self.state.changeset_len

    @property
    def changes(self):
        return super().changes

    def pre_sync(self, sync: SyncEntry) -> bool:  # pylint: disable=too-many-branches
        self.check_revivify(sync)

        if sync.is_discarded:
            self.finished(LOCAL, sync)
            self.finished(REMOTE, sync)
            return True

        sync.get_latest()
        finished = not (sync in self.state.requestset or sync[REMOTE].otype == DIRECTORY)
        return finished

    def get_parent_conflicts(self, sync: SyncEntry, changed) -> List[SyncEntry]:
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
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 storage: Optional['Storage'] = None,
                 tag: Optional[str] = None,
                 shuffle: bool = False,
                 prioritize: Callable[[int, str], int] = None):
        self.requestset = set()
        super().__init__(providers, storage, tag, shuffle, prioritize)

    def smart_sync_ent(self, ent):
        self.requestset.add(ent)

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

    def smart_unsync(self, remote_path):
        # remove path from requestset
        # delete file, if it exists at path
        # reset the sync entry to reflect that the local file is not synced down from the remote
        pass

    def listdir(self, path, side):
        if side == LOCAL:
            pass  # TODO: translate side to remote
        prov = self.providers[LOCAL]
        for ent, rel_path in self.get_kids(path, LOCAL):
            ent_path = ent[LOCAL].path
            if prov.paths_match(prov.dirname(ent_path), path):
                yield ent_path  # TODO: this needs to yield DirInfo, also translate back to local
                
    def changes(self):
        # Filter the changes to just those that are in the requestset, or those whose get_latest is stale viz. change_time
        changes = super().changes()
        for ent in self.requestset:
            if ent[LOCAL].path in changes:
                yield ent

    @property
    def _changeset(self):
        folders = [ent for ent in self._changeset_storage if ent[REMOTE].otype == DIRECTORY]
        return self.requestset.intersection(self._changeset_storage).union(folders)

    # def change(self, age):
    #     super().change(age)
    #     requested_changes = self.requestset.intersection(self._changeset):
    #     if requested_changes:

    def unconditionally_get_latest(self, ent, i):
        # gets enhanced data (mtime, size, etc)
        return super().unconditionally_get_latest(ent, i)


class SmartCloudSync(CloudSync):
    def __init__(self,
                 providers: Tuple['Provider', 'Provider'],
                 roots: Optional[Tuple[str, str]] = None,
                 storage: Optional['Storage'] = None,
                 sleep: Optional[Tuple[float, float]] = None,
                 root_oids: Optional[Tuple[str, str]] = None
                 ):
        super().__init__(providers=providers, roots=roots, storage=storage,
                         sleep=sleep, root_oids=root_oids, smgr_class=SmartSyncManager, state_class=SmartSyncState)

    def smart_unsync(self, path, side):
        path = self._make_path_remote(path, side)

    def smart_sync_ent(self, ent):
        self.state.smart_sync_ent(ent)
        for parent_conflict in self.smgr.get_parent_conflicts(ent, REMOTE):  # ALWAYS remote
            self.smgr.sync_one_entry(parent_conflict)
        self.smgr.sync_one_entry(ent)

    def smart_sync_path(self, path, side):
        path = self._make_path_remote(path, side)
        if side == LOCAL:
            pass  # TODO translate the path to remote
        # q: do we want to take an expiration time here, and do the unsync in our own thread, or let the client do it?
        ents = self.state.lookup_path(REMOTE, path)
        for ent in ents:
            self.smart_sync_ent(ent)

    def listdir(self, path, side):
        path = self._make_path_remote(path, side)

    def _make_path_remote(self, path, side):
        if side == LOCAL:
            path = self.translate(REMOTE, path)  # TODO translate the path to remote
        return path


