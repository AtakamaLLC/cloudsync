from typing import Dict, Any, Optional, overload
import logging
import sqlite3
from threading import Lock
from .state import Storage

log = logging.getLogger(__name__)


class SqliteStorage(Storage):
    """
    Local disk storage using sqlite.
    """
    def __init__(self, filename: str):
        self._mutex = Lock()
        self._filename = filename
        self.db = None
        self.db = self.__db_connect()
        self._ensure_table_exists()

    def __db_connect(self):
        if self.db:
            self.close()

        self.db = sqlite3.connect(self._filename,
                                  uri=self._filename.startswith('file:'),
                                  check_same_thread=self._filename == ":memory:",
                                  timeout=5,
                                  isolation_level=None,
                                  )
        return self.db

    def __db_execute(self, sql, parameters=()):
        # in python 3.6, this will randomly crash unless there's a mutex involved
        # it's not supposed to be a problem... but it is
        with self._mutex:
            try:
                retval = self.db.execute(sql, parameters)
            except sqlite3.OperationalError:
                self.__db_connect()  # reconnect
                retval = self.db.execute(sql, parameters)
            return retval

    def _ensure_table_exists(self):
        self.__db_execute("PRAGMA journal_mode=WAL;")
        self.__db_execute("PRAGMA busy_timeout=5000;")

        # Not using AUTOINCREMENT: http://www.sqlitetutorial.net/sqlite-autoincrement/
        self.__db_execute('CREATE TABLE IF NOT EXISTS cloud (id INTEGER PRIMARY KEY, '
                        'tag TEXT NOT NULL, serialization BLOB)')
        self.__db_execute('CREATE INDEX IF NOT EXISTS cloud_tag_ix on cloud(tag)')
        self.__db_execute('CREATE INDEX IF NOT EXISTS cloud_id_ix on cloud(id)')

    def create(self, tag: str, serialization: bytes) -> Any:
        assert tag is not None
        db_cursor = self.__db_execute('INSERT INTO cloud (tag, serialization) VALUES (?, ?)',
                                    [tag, serialization])
        eid = db_cursor.lastrowid
        return eid

    def update(self, tag: str, serialization: bytes, eid: Any) -> int:
        db_cursor = self.__db_execute('UPDATE cloud SET serialization = ? WHERE id = ? AND tag = ?',
                                    [serialization, eid, tag])
        ret = db_cursor.rowcount
        if ret == 0:
            raise ValueError("id %s doesn't exist" % eid)
        return ret

    def delete(self, tag: str, eid: Any):
        db_cursor = self.__db_execute('DELETE FROM cloud WHERE id = ? AND tag = ?',
                                    [eid, tag])
        if db_cursor.rowcount == 0:
            log.debug("ignoring delete: id %s doesn't exist", eid)
            return

    @overload
    def read_all(self) -> Dict[str, Dict[Any, bytes]]:
        ...

    @overload
    def read_all(self, tag: str) -> Dict[Any, bytes]:             # pylint: disable=arguments-differ
        ...

    def read_all(self, tag: str = None):                          # pylint: disable=arguments-differ
        ret = {}
        if tag is not None:
            query = 'SELECT id, tag, serialization FROM cloud WHERE tag = ?'
            db_cursor = self.__db_execute(query, [tag])
        else:
            query = 'SELECT id, tag, serialization FROM cloud'
            db_cursor = self.__db_execute(query)

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
        db_cursor = self.__db_execute('SELECT serialization FROM cloud WHERE id = ? and tag = ?', [eid, tag])
        for row in db_cursor.fetchall():
            return row
        return None


    def close(self):
        try:
            self.db.close()
        except Exception:
            self.db = None

