from threading import Lock
from typing import Dict, Any, Tuple
import logging
import sqlite3
import os
from cloudsync import Storage

log = logging.getLogger(__name__)


class FileStorage(Storage):
    # extremely inefficient storage persistence in a file, plus pickle is insecure -- put this in a db
    top_lock = Lock()
    lock_dict = dict()

    def __init__(self, filename):
        self.storage_dict = dict()
        # self.cursor: int = 0  # the next eid
        self._filename = filename
        self._load()

    def _save(self):
        with self.top_lock:
            self.db.commit()
            # with open(self._filename, 'wb') as file_obj:
            #     pickle.dump(self.storage_dict, file_obj, 2)

    def _load(self):
        with self.top_lock:
            mk_table = not os.path.exists(self._filename)
            self.db = sqlite3.connect(self._filename)
            self.db_cursor = self.db.cursor()
            if mk_table:
                self.db_cursor.execute('CREATE TABLE cloud (id BLOB, tag TEXT NOT NULL,'
                                       ' serialization BLOB, PRIMARY KEY (id, tag))')
                self.db.commit()
            else:
                self.db_cursor.execute('SELECT * FROM cloud')
                for row in self.db_cursor.fetchall():
                    eid, tag, serialization = row
                    lock: Lock = self.lock_dict.setdefault(tag, Lock())
                    with lock:
                        self.storage_dict.setdefault(tag, dict())[eid] = serialization
            # if os.path.exists(self._filename):
            #     with open(self._filename, 'rb') as file_obj:
            #         storage_dict = pickle.load(file_obj)
            #         if isinstance(storage_dict, dict):
            #             self.storage_dict = storage_dict

    def _get_internal_storage(self, tag: str) -> Tuple[Lock, Dict[int, bytes]]:
        with self.top_lock:
            lock: Lock = self.lock_dict.setdefault(tag, Lock())
        return lock, self.storage_dict.setdefault(tag, dict())

    def create(self, tag: str, serialization: bytes) -> Any:
        # self._load()
        lock, storage = self._get_internal_storage(tag)
        with lock:
            # current_index = self.cursor
            # self.cursor += 1
            eid = os.urandom(16)
            storage[eid] = serialization
            self.db_cursor.execute('INSERT INTO cloud VALUES (?, ?, ?)', [eid, tag, serialization])
            self._save()
            return eid

    def update(self, tag: str, serialization: bytes, eid: Any):
        self._load()
        lock, storage = self._get_internal_storage(tag)
        with lock:
            if eid not in storage:
                raise ValueError("id %s doesn't exist" % eid)
            storage[eid] = serialization
            self.db_cursor.execute('UPDATE cloud SET serialization = ? WHERE id = ? AND tag = ?', [serialization, eid, tag])
            self._save()

    def delete(self, tag: str, eid: Any):
        self._load()
        lock, storage = self._get_internal_storage(tag)
        log.debug("deleting eid%s", eid)
        with lock:
            if eid not in storage:
                log.debug("ignoring delete: id %s doesn't exist", eid)
                return
            del storage[eid]
            self.db_cursor.execute('DELETE FROM cloud WHERE id = ? AND tag = ?', [eid, tag])
            self._save()

    def read_all(self, tag: str) -> Dict[Any, bytes]:
        self._load()
        lock, storage = self._get_internal_storage(tag)
        with lock:
            ret: Dict[Any, bytes] = storage.copy()
            return ret
