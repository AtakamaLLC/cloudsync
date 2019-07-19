import os
import time
import logging
import tempfile

from typing import Optional

__all__ = ['SyncManager', 'SyncState', 'LOCAL', 'REMOTE', 'FILE', 'DIRECTORY']

from pycloud.exceptions import CloudFileNotFoundError 

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
        self.sync_hash: Optional[bytes] = None           # hash at last sync
        self.sync_path: Optional[str] = None           # path at last sync

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
        self.otype = otype

    def __getitem__(self, i):
        return self.__states[i]

    def update(self, providers):
        for i in (LOCAL, REMOTE):
            if self[i].changed:
                # get latest info from provider
                if self.otype == FILE:
                    self[i].hash = providers[i].hash_oid(self[i].oid)
                    self[i].exists = self[i].hash
                else:
                    self[i].exists = providers[i].exists(self[i].oid)
            else:
                # trust local sync state
                self[i].exists = self.sync_exists
                if self[i].sync_hash:
                    self[i].hash = self[i].sync_hash
                    self[i].path = self[i].sync_path
                else:
                    self[i].hash = None

    def hash_conflict(self):
        if self[0].sync_hash and self[1].sync_hash:
            return self[0].hash != self[0].sync_hash and self[1].hash != self[1].sync_hash
        return False

    def path_conflict(self):
        if self[0].sync_path and self[1].sync_path:
            return self[0].path != self[0].sync_path and self[1].path != self[1].sync_path
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
        return list(self._changeset)

    def get_all(self):
        ents = set()
        for ent in self._oids[LOCAL].values():
            ents.add(ent)
        for ent in self._oids[REMOTE].values():
            ents.add(ent)
        return ents

    def synced(self, ent):
        self._changeset.remove(ent)

    def entry_count(self):
        return len(self.get_all())

class SyncManager(Runnable):
    def __init__(self, syncs, providers, translate):
        self.syncs = syncs
        self.providers = providers
        self.translate = translate
        self.tempdir = tempfile.mkdtemp(suffix=".pycloud")

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
            if sync[i].changed:
                self.embrace_change(sync, i, other(i))

    def temp_file(self):
        # prefer big random name over NamedTemp which can infinite loop in odd situations!
        return os.path.join(self.tempdir, os.urandom(32).hex())

    def embrace_change(self, sync, changed, synced):
        log.debug("HERE!!!!!!!!!!!!!!")

        if not sync[changed].exists:
            # see if there are other entries for the same path, but other ids
            ents = self.syncs.get_path(changed, sync[changed].path)

            if len(ents) == 1:
                assert ents[0] == sync
                self.providers[synced].delete(sync[other].oid)

            self.syncs.remove(sync)
            return
        
        if sync[changed].path != sync[changed].sync_path:
            if not sync[changed].sync_path:
                assert not sync[changed].sync_hash
                # looks like a new file
                
                sync.temp_file = self.temp_file()

                assert sync[changed].oid

                try:
                    self.providers[changed].download(sync[changed].oid, open(sync.temp_file, "wb"))
                except CloudFileNotFoundError:
                    log.debug("download %s failed fnf, switch to not exists", self.providers[changed])
                    sync.exists = False
                    return

                if sync[synced].oid:
                    try:
                        self.providers[synced].upload(sync[synced].oid, open(sync.temp_file, "rb"))
                        return
                    except CloudFileNotFoundError:
                        log.debug("upload %s failed fnf, try by path", self.providers[synced])

                try:
                    self.providers[synced].create(sync[synced].path, open(sync.temp_file, "rb"))
                    log.debug("upload %s %s by path", self.providers[synced], self.translate(synced, sync[changed].path))
                    self.syncs.synced(sync)
                    return
                except CloudFileNotFoundError:
                    log.debug("upload %s failed fnf, mkdir needed")
                    raise NotImplementedError("TODO mkdir, and make syncs etc")

        if sync[changed].hash != sync[changed].sync_hash:
            raise "HASH"
           
        raise "NOTHING"


    def handle_hash_conflict(self, sync):
        raise NotImplementedError()

    def handle_path_conflict(self, sync):
        raise NotImplementedError()
