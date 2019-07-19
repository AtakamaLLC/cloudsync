import time

from abc import ABC, abstractmethod
from typing import NamedTuple, Any

def time_helper(secs, sleep=None):
    end = time.monotonic() + secs
    while end >= time.monotonic():
        yield True
        if sleep:
            time.sleep(sleep)

class Runnable(ABC):
    def run(self,*, timeout=None, until=None):
        while time_helper(timeout, sleep=0.1):
            if until is not None and until():
                break

            try:
                self.do()
            except Exception:
                log.exception("unhandled exception in %s", self.__class__)

    @abstractmethod
    def do():
        ...

    def stop():
        self.stopped = True

class State(NamedTuple):
    exists: bool
    hash: bytes
    path: str
    change: float
    id: str


class Sync:
    FILE = "file"
    DIRECTORY = "dir"

    def __init__(self):
        self.states = (State(), State())
        self.sync_exists = None
        self.sync_hash = None
        self.sync_path = None

    def update(self, providers):
        for i in (0,1):
            if self.states[i].change:
                # get latest info from provider
                self.states[i].hash = None
                self.states[i].path = self.states[i].path
                if self.file_type == Sync.FILE:
                    self.states[i].hash = providers[i].hash(self.states[i].id)
                    self.states[i].exists = self.states[i].hash
                else:
                    self.states[i].exists = providers[i].exists(self.states[i].id)
            else:
                # trust local sync state
                self.states[i].exists = self.sync_exists
                self.states[i].hash  = self.sync_hash[i]
                self.states[i].path = self.sync_path[i]

    def hash_conflict():
        if self.sync.sync_hash:
            return self.states[0].hash != sync.sync_hash[0] and self.states[1].hash != sync.sync_hash[1]

    def path_conflict():
        if self.sync.sync_path:
            return self.states[0].path != sync.sync_path[0] and self.states[1].path != sync.sync_path[1]

class SyncManager(Runnable):
    def __init__(self, syncs, providers):
        self.syncs = syncs
        self.providers = providers

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

        for i in (0,1):
            if sync.states[i].change:
                # one side is deleted
                # see if there are other entries for the same path, but other ids
                dups = self.state.get(i, path=sync.states[i].path, all=True)

                if len(dups) == 1:
                    self.providers[1-i].remove(sync.states[1-i].id)
                self.states.remove(sync)
                return                 

class SyncState:
    pass



