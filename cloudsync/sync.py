import os
import time
import logging
import tempfile
import shutil

from typing import Optional

__all__ = ['SyncManager', 'SyncState', 'LOCAL', 'REMOTE', 'FILE', 'DIRECTORY']

from cloudsync.exceptions import CloudFileNotFoundError 

from .runnable import Runnable

log = logging.getLogger(__name__)

# state of a single object


class Reprable:
    def __repr__(self):
        return self.__class__.__name__ + str(self.__dict__)

class SideState(Reprable):                            # pylint: disable=too-few-public-methods
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


def other_side(index):
    return 1-index


FILE = "file"
DIRECTORY = "dir"

# single entry in the syncs state collection


class SyncEntry(Reprable):
    def __init__(self, otype):
        self.__states = (SideState(), SideState())
        self.sync_exists = None
        self.otype = otype
        self.temp_file = None

    def __getitem__(self, i):
        return self.__states[i]

    def update(self, providers):
        for i in (LOCAL, REMOTE):
            if self[i].changed:
                # get latest info from provider
                if self.otype == FILE:
                    self[i].hash = providers[i].hash_oid(self[i].oid)
                    self[i].exists = bool(self[i].hash)
                else:
                    self[i].exists = providers[i].exists_oid(self[i].oid)
            else:
                # trust local sync state
                self[i].exists = self.sync_exists
                if self[i].sync_hash:
                    self[i].hash = self[i].sync_hash
                    self[i].path = self[i].sync_path
                else:
                    self[i].hash = None
            log.debug("updated state %s %s", self[LOCAL], self[REMOTE])

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

        if exists is not None:
            ent[side].exists = exists
            
        ent[side].changed = time.time()

        log.debug("changed %s", ent)

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
        self.providers[LOCAL]._sname = "local"
        self.providers[REMOTE]._sname = "remote"
        self.translate = translate
        self.tempdir = tempfile.mkdtemp(suffix=".cloudsync")

        assert len(self.providers) == 2

    def do(self):
        for sync in self.syncs.changes():
            self.sync(sync)

    def done(self):
        log.info("cleanup %s", self.tempdir)
        shutil.rmtree(self.tempdir)

    def sync(self, sync):
        sync.update(self.providers)

        if sync.hash_conflict():
            self.handle_hash_conflict(sync)

        if sync.path_conflict():
            self.handle_path_conflict(sync)

        for i in (LOCAL, REMOTE):
            if sync[i].changed:
                self.embrace_change(sync, i, other_side(i))

    def temp_file(self, ohash):
        # prefer big random name over NamedTemp which can infinite loop in odd situations!
        return os.path.join(self.tempdir, ohash)

    def finished(self, side, sync):
        sync[side].changed = None
        self.syncs.synced(sync)

        if sync.temp_file:
            try:
                os.unlink(sync.temp_file)
            except:
                pass
            sync.temp_file = None

    def download_changed(self, changed, sync):
        sync.temp_file = sync.temp_file or self.temp_file(sync[changed].hash)

        assert sync[changed].oid

        if os.path.exists(sync.temp_file):
            return True

        try:
            self.providers[changed].download(sync[changed].oid, open(sync.temp_file + ".tmp", "wb"))
            os.rename(sync.temp_file + ".tmp", sync.temp_file)
            return True
        except CloudFileNotFoundError:
            log.debug("download from %s failed fnf, switch to not exists", self.providers[changed]._sname)
            sync[changed].exists = False
            return False

    def mkdir_synced(self, changed, sync):
        synced = other_side(changed)
        try:
            translated_path = self.translate(synced, sync[changed].path)
            oid = self.providers[synced].mkdir(translated_path)
            log.debug("mkdir %s as path %s", self.providers[synced]._sname, sync[synced].sync_path)
            sync[synced].oid = oid
            sync[synced].sync_path = translated_path
            sync[changed].sync_path = sync[changed].path
            self.finished(changed, sync)
        except CloudFileNotFoundError:
            log.debug("upload to %s failed fnf, TODO fix mkdir code and stuff", self.providers[synced]._sname)
            raise NotImplementedError("TODO mkdir, and make syncs etc")

    def upload_synced(self, changed, sync):
        synced = other_side(changed)
        try:
            info = self.providers[synced].upload(sync[synced].oid, open(sync.temp_file, "rb"))
            log.debug("upload to %s as path %s", self.providers[synced]._sname, sync[synced].sync_path)
            sync[synced].sync_hash = info.hash
            if info.path:
                sync[synced].sync_path = info.path
            else:
                sync[synced].sync_path = sync[synced].path
            sync[synced].oid = info.oid
            sync[changed].sync_hash = sync[changed].hash
            sync[changed].sync_path = sync[changed].path
            self.finished(changed, sync)
        except CloudFileNotFoundError:
            log.debug("upload to %s failed fnf, TODO fix mkdir code and stuff", self.providers[synced]._sname)
            raise NotImplementedError("TODO mkdir, and make syncs etc")

    def create_synced(self, changed, sync):
         synced = other_side(changed)
         try:
            translated_path = self.translate(synced, sync[changed].path)
            info = self.providers[synced].create(translated_path, open(sync.temp_file, "rb"))
            log.debug("create on %s as path %s", self.providers[synced]._sname, translated_path)
            sync[synced].oid = info.oid
            sync[synced].sync_hash = info.hash
            if info.path:
                sync[synced].sync_path = info.path
            else:
                sync[synced].sync_path = translated_path
            sync[changed].sync_hash = sync[changed].hash
            sync[changed].sync_path = sync[changed].path
            self.finished(changed, sync)
         except CloudFileNotFoundError:
            log.debug("create on %s failed fnf, mkdir needed", self.providers[synced]._sname)
            raise NotImplementedError("TODO mkdir, and make syncs etc")

    def embrace_change(self, sync, changed, synced):
        log.debug("changed %s", sync)

        if not sync[changed].exists:
            # see if there are other entries for the same path, but other ids
            ents = list(self.syncs.lookup_path(changed, sync[changed].path))

            if len(ents) == 1:
                assert ents[0] == sync
                self.providers[synced].delete(sync[synced].oid)

            sync[synced].exists = False

            self.finished(changed, sync)
            return
        
        if sync[changed].path != sync[changed].sync_path:
            if not sync[changed].sync_path:
                assert not sync[changed].sync_hash
                # looks like a new file
             
                if sync.otype == DIRECTORY:
                    self.mkdir_synced(changed, sync)
                    return
                
                if not self.download_changed(changed, sync):
                    return

                if sync[synced].oid:
                    upload_synced(changed, sync)
                    return

                self.create_synced(changed, sync)
                return
            else:
                assert sync[synced].oid
                translated_path = self.translate(synced, sync[changed].path)
                log.debug("rename %s %s", sync[synced].sync_path, translated_path)
                self.providers[synced].rename(sync[synced].oid, translated_path)
                sync[synced].path = translated_path
                sync[synced].sync_path = translated_path
                sync[changed].sync_path = sync[changed].path
                self.finished(changed, sync)
                return

        if sync[changed].hash != sync[changed].sync_hash:
            # not a new file, which means we must have last sync info

            assert sync[synced].oid

            self.download_changed(changed, sync)
            self.upload_synced(changed, sync)
            return 

        log.info("nothing changed %s, but changed is true", sync)


    def handle_hash_conflict(self, sync):
        raise NotImplementedError()

    def handle_path_conflict(self, sync):
        raise NotImplementedError()
