import time
import logging

from typing import Optional

from .runnable import Runnable

log = logging.getLogger(__name__)

# state of a single object


class SideState:                            # pylint: disable=too-few-public-methods
    def __init__(self):
        self.exists: bool = True            # exists at provider
        self.hash: Optional[bytes] = None           # hash at provider
        self.path: Optional[str] = None           # path at provider
        self.oid: Optional[str] = None           # oid at provider
        # time of last change (we maintain this)
        self.changed: Optional[float] = None


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
        self.sync_hash = []
        self.sync_path = []
        self.otype = otype

    def __getitem__(self, i):
        return self.__states[i]

    def update(self, providers):
        for i in (LOCAL, REMOTE):
            if self[i].change:
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
                self[i].hash = self.sync_hash[i]
                self[i].path = self.sync_path[i]

    def hash_conflict(self):
        if self.sync_hash:
            return self[0].hash != self.sync_hash[0] and self[1].hash != self.sync_hash[1]
        return False

    def path_conflict(self):
        if self.sync_path:
            return self[0].path != self.sync_path[0] and self[1].path != self.sync_path[1]
        return False


class SyncState:
    def __init__(self):
        self._oids = ({}, {})
        self._paths = ({}, {})
        self._changeset = set()

    def _change_path(self, side, ent, path):
        assert type(ent) is SyncEntry

        assert ent[side].oid

        if ent[side].path:
            if ent[side].path in self._paths[side]:
                self._paths[side][ent[side].path].pop(ent[side].oid, None)
            if not self._paths[side][ent[side].path]:
                del self._paths[side][ent[side].path]
        if path not in self._paths[side]:
            self._paths[side][path] = {}
        self._paths[side][path][ent[side].oid] = ent
        ent[side].path = path

    def _change_oid(self, side, ent, oid):
        assert type(ent) is SyncEntry

        if ent[side].oid:
            self._oids[side].pop(ent[side].oid, None)
        self._oids[side][oid] = ent
        ent[side].oid = oid

    def lookup_oid(self, side, oid):
        try:
            return self._oids[side][oid]
        except KeyError:
            return []

    def lookup_path(self, side, path):
        try:
            return self._paths[side][path].values()
        except KeyError:
            return []

    def rename_dir(self, side, from_dir, to_dir, is_subpath, replace_path):
        """
        when a directory changes, utility to rename all kids
        """
        remove = []

        for path, sub in self._paths[side].items():
            if is_subpath(from_dir, sub.path):
                sub.path = replace_path(sub.path, from_dir, to_dir)
                remove.append(path)
                self._paths[side][sub.path] = sub

        for path in remove:
            self._paths[side].pop(path)

    def update(self, side, otype, oid, path=None, hash=None, exists=True):
        ent = self.lookup_oid(side, oid)

        if not ent:
            ent = SyncEntry(otype)

        if oid is not None:
            self._change_oid(side, ent, oid)

        if path is not None:
            self._change_path(side, ent, path)

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
            self.handle_hash_conflict(sync)

        if sync.path_conflict():
            self.handle_path_conflict(sync)

        for i in (LOCAL, REMOTE):
            if sync.states[i].change:
                self.embrace_change(sync, i, other(i))

    def embrace_change(self, sync, changed, synced):
        # see if there are other entries for the same path, but other ids
        ents = self.syncs.get_path(changed, sync[changed].path)

        if len(ents) == 1:
            assert ents[0] == sync
            self.providers[synced].delete(sync[other].oid)

        self.syncs.remove(sync)

    def handle_hash_conflict(self, sync):
        raise NotImplementedError()

    def handle_path_conflict(self, sync):
        raise NotImplementedError()
