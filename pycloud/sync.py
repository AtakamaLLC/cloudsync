import time
from .runnable import Runnable

# state of a single object
class SideState:
    def __init__(self):
        self.exists: bool   = True            # exists at provider
        self.hash: Optional[bytes]    = None           # hash at provider
        self.path: Optional[str]      = None           # path at provider
        self.oid: Optional[str]       = None           # oid at provider
        self.changed: Optional[float] = None          # time of last change (we maintain this)

# these are not really local or remote
# but it's easier to reason about using these labels
LOCAL = 0
REMOTE = 1

def other(index):
    return 1-index

FILE = "file"
DIRECTORY = "dir"

# single entry in the syncs state collection
class SyncEntry:
    def __init__(self, otype):
        self.__states = (SideState(), SideState())
        self.sync_exists = None
        self.sync_hash = None
        self.sync_path = None
        self.otype = otype

    def __getitem__(self, i):
        return self.__states[i]

    def update(self, providers):
        for i in (LOCAL,REMOTE):
            if self.states[i].change:
                # get latest info from provider
                self[i].hash = None
                self[i].path = self[i].path
                if self.otype == FILE:
                    self[i].hash = providers[i].hash(self[i].oid)
                    self[i].exists = self[i].hash
                else:
                    self[i].exists = providers[i].exists(self[i].oid)
            else:
                # trust local sync state
                self[i].exists = self.sync_exists
                self[i].hash  = self.sync_hash[i]
                self[i].path = self.sync_path[i]

    def hash_conflict():
        if self.sync.sync_hash:
            return self[0].hash != sync.sync_hash[0] and self[1].hash != sync.sync_hash[1]

    def path_conflict():
        if self.sync.sync_path:
            return self[0].path != sync.sync_path[0] and self[1].path != sync.sync_path[1]

class SyncState:
    def __init__(self):
        self._oids = {}
        self._paths = {}
        self._changeset = set()

    def _change_path(side, ent, path):
        self._paths[side][ent.path].pop(ent.oid)
        self._paths[side][path][ent.oid] = ent
        if not self._paths[side][ent.path]:
            del self._paths[side][ent.path]
        ent[side].path = path

    def _change_oid(side, ent, oid):
        self._oids[side].pop(ent.oid)
        self._oids[side][ent.oid] = ent
        ent[side].oid = oid
 
    def lookup_oid(self, side, oid):
        return self._oids[side][oid]

    def lookup_path(self, side, path):
        return self._paths[side][path]

    def rename_dir(side, from_dir, to_dir, is_subpath, replace_path):
        """
        When a directory changes, rename all kids
        """
        remove = []

        for path, sub in self._paths.items():
            if is_subpath(from_dir, sub.path):
                sub.path = replace_path(sub.path, from_dir, to_dir)
                remove.append(path)
                self._paths[sub.path] = sub

        for path in remove:
            self._paths.pop(path)

    def update(self, side, otype, path=None, oid=None, hash=None, exists=True):
        try:
            if oid is not None:
                 ents = self.lookup_oid(side, oid)
            else:
                 ents = self.lookup_path(side, path)
        except KeyError:
            ents = []

        if not ents:
            ents = [SyncEntry(otype)]

        for ent in ents:
            if path is not None:
                if ent[side].path:
                    self._change_path(side, ent, path)
                else:
                    ent[side].path = path

            if oid is not None:
                if ent[side].oid:
                    self._change_oid(side, ent, oid)
                else:
                    ent[side].oid = oid

            if hash is not None:
                ent[side].hash = hash

            ent[side].exists = exists
            ent[side].changed = time.time()

            self._changeset.add(ent)

    def changes(self):
        return self._changeset 

    def synced(self, entries):
        for ent in entries:
            if not ent.changed:
                self._changeset.remove(ent)

class SyncManager(Runnable):
    def __init__(self, syncs, providers, translate):
        self.syncs = syncs
        self.providers = providers
        self.translate = translate

        assert len(self.providers) == 2

    def do(self):
        for sync in self.syncs.changes():
            self.sync(sync)

    def sync(self, sync):
        sync.update(self.providers)

        if sync.hash_conflict():
            self.handle_hash_conflict(sync, info)

        if sync.path_conflict():
            self.handle_path_conflict(sync, info)

        for i in (LOCAL, REMOTE):
            if sync.states[i].change:
                self.embrace_change(sync, i, other(i))

    def embrace_change(self, sync, changed, other):
        # see if there are other entries for the same path, but other ids
        ents = self.syncs.get_path(changed, sync.states[changed].path)

        if len(ents) == 1:
            assert ent[0] == sync
            self.providers[other].delete(sync.states[other].oid)

        self.states.remove(sync)



