import time

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

class SyncSummary(NamedTuple):
    local_exists: bool
    local_hash: Any
    local_path: str
    remote_exists: bool
    remote_hash: Any
    remote_path: str

class Sync:
    FILE = "file"
    DIRECTORY = "dir"

    def summary(self, local_provider, remote_provider):
        if self.remote_change:
            remote_exists = remote_provider.exists(self.remote_id)
            remote_hash = None
            remote_path = self.remote_path
            
            if remote_exists:
                if self.file_type == Sync.FILE:
                    remote_hash = provider.remote_hash(self.remote_id)
                    if self.new_remote_path:
                        remote_path = self.new_remote_path
                    else:
                        remote_path = self.remote_path
        else:
            remote_exists = self.sync_exists
            remote_hash  = self.sync_hash
            remote_path = self.sync_remote_path


        if self.local_change:
            local_exists = local_provider.exists(self.local_id)
            local_hash = None
            local_path = self.local_path
            if local_exists:
                if self.file_type == Sync.FILE:
                    local_hash = local_provider.local_hash(self.local_id)
                    if self.new_local_path:
                        local_path = self.new_local_path
                    else:
                        local_path = self.local_path
        else:
            local_exists = self.sync_exists
            local_hash  = self.sync_hash
            local_path = self.sync_local_path

        return SyncSummary(local_exists, local_hash, local_path, remote_exists, remote_hash, remote_path)

class SyncManager(Runnable):
    def __init__(self, state, local_provider, remote_provider):
        self.state = state
        self.local_provider = local_provider
        self.remote_provider = remote_provider

    def do(self):
        for sync in self.state.changes():
            self.sync(sync)

    def sync(self, sync):
        info = sync.summary(self.local_provider, self.remote_provider)

        if info.local_hash != sync.sync_hash and info.remote_hash != sync.sync_hash:
            self.handle_hash_conflict(sync, info)

        if sync.sync_path:
            if info.local_path != sync.sync_local_path and info.remote_path !=  != sync.sync_remote_path:
                self.handle_name_conflict(sync, info)

        if sync.remote_change and not info.remote_exists:
                # deleted in remote
                dups = self.state.get(local_path=info.local_path, exists=False)
                if len(dups) == 1 and dups[0].remote_id = sync.remote_id:
                    local_provider.remove(sync.local_id)
                self.state.remove(sync.sync_id)
                return                 

        if sync.local_change and not info.local_exists:
                # deleted in remote
                dups = self.state.get(remote_path=info.remote_path, exists=False)
                if len(dups) == 1 and dups[0].local_id = sync.local_id:
                    remote_provider.remove(sync.remote_id)
                self.state.remove(sync.sync_id)
                return                 
 

class SyncState:
    pass



