from threading import Lock
from typing import Dict, Any, Tuple
import logging
from cloudsync import CloudSync, SyncState, Storage, LOCAL, REMOTE

log = logging.getLogger(__name__)


class MockStorage(Storage):  # Does not actually persist the data... but it's just a mock
    top_lock = Lock()
    lock_dict = dict()

    def __init__(self, storage_dict: Dict[str, Dict[int, bytes]]):
        self.storage_dict = storage_dict
        self.cursor: int = 0  # the next eid

    def _get_internal_storage(self, tag: str) -> Tuple[Lock, Dict[int, bytes]]:
        with self.top_lock:
            lock: Lock = self.lock_dict.setdefault(tag, Lock())
        return lock, self.storage_dict.setdefault(tag, dict())

    def create(self, tag: str, serialization: bytes) -> Any:
        lock, storage = self._get_internal_storage(tag)
        with lock:
            current_index = self.cursor
            self.cursor += 1
            storage[current_index] = serialization
            return current_index

    def update(self, tag: str, serialization: bytes, eid: Any):
        lock, storage = self._get_internal_storage(tag)
        with lock:
            if eid not in storage:
                raise ValueError("id %s doesn't exist" % eid)
            storage[eid] = serialization

    def delete(self, tag: str, eid: Any):
        lock, storage = self._get_internal_storage(tag)
        log.debug("deleting eid%s", eid)
        with lock:
            if eid not in storage:
                log.debug("ignoring delete: id %s doesn't exist" % eid)
                return
            del storage[eid]

    def read_all(self, tag: str) -> Dict[Any, bytes]:
        lock, storage = self._get_internal_storage(tag)
        with lock:
            ret: Dict[Any, bytes] = storage.copy()
            return ret
