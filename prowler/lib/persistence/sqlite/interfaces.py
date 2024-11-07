import abc
import sqlite3
import tempfile

from ..interfaces import _InterfaceGenericStructure

DEFAULT_CACHE_SIZE = 2000


class GenericSQLiteStructure(_InterfaceGenericStructure, metaclass=abc.ABCMeta):

    def __init__(self, cache_size=2000):
        self._tmp_path = tempfile.NamedTemporaryFile(prefix="prowler-structure-")
        self.db_name = self._tmp_path.name
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.cache_size = cache_size or DEFAULT_CACHE_SIZE
        self.__configure_cache__()
        self.__create_table__()

    def __configure_cache__(self):
        with self.conn:
            # TODO: fix this query adding a parameter
            self.conn.execute(f"PRAGMA cache_size = {-self.cache_size}")
            self.conn.execute("PRAGMA journal_mode = WAL")

    def __len__(self):
        cursor = self.conn.execute("SELECT COUNT(*) FROM structure_items")
        return cursor.fetchone()[0]

    def __del__(self):
        self.close()
        self._tmp_path.close()

    def close(self):
        self.conn.close()

    def clear(self):
        with self.conn:
            self.conn.execute("DELETE FROM structure_items")


__all__ = ("GenericSQLiteStructure",)
