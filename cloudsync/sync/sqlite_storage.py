from typing import Dict, Any, Optional
import logging
import sqlite3
from cloudsync import Storage
from cloudsync.log import TRACE

log = logging.getLogger(__name__)


class SqliteStorage(Storage):
    def __init__(self, filename: str):
        self._filename = filename
        self._ensure_table_exists()

    def _ensure_table_exists(self):
        self.db = sqlite3.connect(self._filename,
                                  uri=self._filename.startswith('file:'),
                                  check_same_thread=self._filename == ":memory:",
                                  timeout=5,
                                  isolation_level=None,
                                  )
        self.db.execute("PRAGMA journal_mode=WAL;")
        self.db.execute("PRAGMA busy_timeout=5000;")

        # Not using AUTOINCREMENT: http://www.sqlitetutorial.net/sqlite-autoincrement/
        self.db.execute('CREATE TABLE IF NOT EXISTS cloud (id INTEGER PRIMARY KEY, '
                        'tag TEXT NOT NULL, serialization BLOB)')

    def create(self, tag: str, serialization: bytes) -> Any:
        db_cursor = self.db.execute('INSERT INTO cloud (tag, serialization) VALUES (?, ?)',
                                    [tag, serialization])
        eid = db_cursor.lastrowid
        return eid

    def update(self, tag: str, serialization: bytes, eid: Any) -> int:
        log.log(TRACE, "updating eid%s", eid)
        db_cursor = self.db.execute('UPDATE cloud SET serialization = ? WHERE id = ? AND tag = ?',
                                    [serialization, eid, tag])
        ret = db_cursor.rowcount
        if ret == 0:
            raise ValueError("id %s doesn't exist" % eid)
        return ret

    def delete(self, tag: str, eid: Any):
        log.log(TRACE, "deleting eid%s", eid)
        db_cursor = self.db.execute('DELETE FROM cloud WHERE id = ? AND tag = ?',
                                    [eid, tag])
        if db_cursor.rowcount == 0:
            log.debug("ignoring delete: id %s doesn't exist", eid)
            return

    def read_all(self, tag: str) -> Dict[Any, bytes]:
        ret = {}
        db_cursor = self.db.execute('SELECT id, serialization FROM cloud WHERE tag = ?', [tag])
        for row in db_cursor.fetchall():
            eid, serialization = row
            ret[eid] = serialization
        return ret

    def read(self, tag: str, eid: Any) -> Optional[bytes]:
        db_cursor = self.db.execute('SELECT serialization FROM cloud WHERE id = ? and tag = ?', [eid, tag])
        for row in db_cursor.fetchall():
            return row
        return None
