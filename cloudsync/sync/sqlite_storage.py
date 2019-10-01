from typing import Dict, Any, Optional
import logging
import sqlite3
from .state import Storage

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
        self.db.execute('CREATE INDEX IF NOT EXISTS cloud_tag_ix on cloud(tag)')
        self.db.execute('CREATE INDEX IF NOT EXISTS cloud_id_ix on cloud(id)')

    def create(self, tag: str, serialization: bytes) -> Any:
        assert tag is not None
        db_cursor = self.db.execute('INSERT INTO cloud (tag, serialization) VALUES (?, ?)',
                                    [tag, serialization])
        eid = db_cursor.lastrowid
        return eid

    def update(self, tag: str, serialization: bytes, eid: Any) -> int:
        db_cursor = self.db.execute('UPDATE cloud SET serialization = ? WHERE id = ? AND tag = ?',
                                    [serialization, eid, tag])
        ret = db_cursor.rowcount
        if ret == 0:
            raise ValueError("id %s doesn't exist" % eid)
        return ret

    def delete(self, tag: str, eid: Any):
        db_cursor = self.db.execute('DELETE FROM cloud WHERE id = ? AND tag = ?',
                                    [eid, tag])
        if db_cursor.rowcount == 0:
            log.debug("ignoring delete: id %s doesn't exist", eid)
            return

    def read_all(self, tag: str = None) -> Dict[Any, bytes]:
        ret = {}
        if tag is not None:
            query = 'SELECT id, tag, serialization FROM cloud WHERE tag = ?'
            db_cursor = self.db.execute(query, [tag])
        else:
            query = 'SELECT id, tag, serialization FROM cloud'
            db_cursor = self.db.execute(query)

        for row in db_cursor.fetchall():
            eid, row_tag, row_serialization = row
            if tag is not None:
                ret[eid] = row_serialization
            else:
                if row_tag not in ret:
                    ret[row_tag] = {}
                ret[row_tag][eid] = row_serialization
        return ret

    def read(self, tag: str, eid: Any) -> Optional[bytes]:
        db_cursor = self.db.execute('SELECT serialization FROM cloud WHERE id = ? and tag = ?', [eid, tag])
        for row in db_cursor.fetchall():
            return row
        return None
