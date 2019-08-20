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
        # self.cursor: int = 0  # the next eid
        self._filename = filename
        self._ensure_table_exists()

    def _save(self):
        self.db.commit()

    def _ensure_table_exists(self):
        with self.top_lock:
            self.db = sqlite3.connect(self._filename, uri=self._filename.startswith('file:'))
            self.db_cursor = self.db.cursor()
            # Not using AUTOINCREMENT: http://www.sqlitetutorial.net/sqlite-autoincrement/
            self.db_cursor.execute('CREATE TABLE IF NOT EXISTS cloud (id INTEGER PRIMARY KEY, '
                                   'tag TEXT NOT NULL, serialization BLOB)')
            self._save()

    def create(self, tag: str, serialization: bytes) -> Any:
        with self.top_lock:
            self.db_cursor.execute('INSERT INTO cloud (tag, serialization) VALUES (?, ?)', [tag, serialization])
            eid = self.db_cursor.lastrowid
            self._save()
            return eid

    def update(self, tag: str, serialization: bytes, eid: Any):
        with self.top_lock:
            self.db_cursor.execute('UPDATE cloud SET serialization = ? WHERE id = ? AND tag = ?', [serialization, eid, tag])
            if self.db_cursor.rowcount == 0:
                raise ValueError("id %s doesn't exist" % eid)
            self._save()

    def delete(self, tag: str, eid: Any):
        log.debug("deleting eid%s", eid)
        with self.top_lock:
            self.db_cursor.execute('DELETE FROM cloud WHERE id = ? AND tag = ?', [eid, tag])
            if self.db_cursor.rowcount == 0:
                log.debug("ignoring delete: id %s doesn't exist", eid)
                return
            self._save()

    def read_all(self, tag: str) -> Dict[Any, bytes]:
        with self.top_lock:
            ret = {}
            self.db_cursor.execute('SELECT id, serialization FROM cloud WHERE tag = ?', [tag])
            for row in self.db_cursor.fetchall():
                eid, serialization = row
                ret[eid] = serialization
            return ret
