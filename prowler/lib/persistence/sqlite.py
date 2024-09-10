import os
import sqlite3
import tempfile

import dill

DEFAULT_CACHE_SIZE = 2000


class SQLiteDict:

    def __init__(self, cache_size=2000):
        self._tmp_path = tempfile.NamedTemporaryFile(prefix='prowler-dict-')
        self.db_name = self._tmp_path.name
        self.conn = sqlite3.connect(self.db_name)
        self.cache_size = cache_size or DEFAULT_CACHE_SIZE
        self._configure_cache()
        self._create_table()

    def _configure_cache(self):
        with self.conn:
            self.conn.execute(f'PRAGMA cache_size = {-self.cache_size}')
            self.conn.execute('PRAGMA journal_mode = WAL')

    def _create_table(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS dict_items (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            ''')

    def __getitem__(self, key):
        with self.conn:
            cursor = self.conn.execute('SELECT value FROM dict_items WHERE key = ?', (key,))
            row = cursor.fetchone()
            if row:
                return dill.loads(row[0])
            else:
                raise KeyError(key)

    def __contains__(self, key):
        with self.conn:
            cursor = self.conn.execute('SELECT 1 FROM dict_items WHERE key = ?', (key,))
            return cursor.fetchone() is not None

    def __setitem__(self, key, value):
        self.conn.execute('INSERT OR REPLACE INTO dict_items (key, value) VALUES (?, ?)', (key, dill.dumps(value)))

    def __len__(self):
        cursor = self.conn.execute('SELECT COUNT(*) FROM dict_items')
        return cursor.fetchone()[0]

    def __delitem__(self, key):
        with self.conn:
            cursor = self.conn.execute('DELETE FROM dict_items WHERE key = ?', (key,))
            if cursor.rowcount == 0:
                raise KeyError(f'Key {key} not found')

    def __del__(self):
        self.close()
        self._tmp_path.close()

    def close(self):
        self.conn.close()

    def clear(self):
        with self.conn:
            self.conn.execute('DELETE FROM dict_items')

    def items(self):
        cursor = self.conn.execute('SELECT key, value FROM dict_items')
        for row in cursor:
            yield row[0], dill.loads(row[1])

    def keys(self):
        cursor = self.conn.execute('SELECT key FROM dict_items')
        for row in cursor:
            yield row[0]

    def values(self):
        cursor = self.conn.execute('SELECT value FROM dict_items')
        for row in cursor:
            yield dill.loads(row[0])

    def pop(self, key, default=None):
        try:
            with self.conn:
                cursor = self.conn.execute('SELECT value FROM dict_items WHERE key = ?', (key,))
                row = cursor.fetchone()
                if row:
                    value = dill.loads(row[0])
                    self.conn.execute('DELETE FROM dict_items WHERE key = ?', (key,))
                    return value
                elif default is not None:
                    return default
                else:
                    raise KeyError(key)
        except sqlite3.Error:
            if default is not None:
                return default
            raise KeyError(key)

    def popitem(self):
        with self.conn:
            cursor = self.conn.execute('SELECT key, value FROM dict_items LIMIT 1')
            row = cursor.fetchone()
            if row:
                key, value = row[0], dill.loads(row[1])
                self.conn.execute('DELETE FROM dict_items WHERE key = ?', (key,))
                return (key, value)
            raise KeyError('Dictionary is empty')

    def update(self, other=None, **kwargs):
        if other is not None:
            if hasattr(other, 'items'):
                for key, value in other.items():
                    self[key] = value
            else:
                for key, value in other:
                    self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    @classmethod
    def fromkeys(cls, iterable, value=None):
        dictionary = cls()
        for key in iterable:
            dictionary[key] = value
        return dictionary

    def copy(self):
        new_dict = SQLiteDict()
        for key, value in self.items():
            new_dict[key] = value
        return new_dict

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            self[key] = default
            return default


class SQLiteList:

    def __init__(self, cache_size=2000):
        # Crea un nuevo archivo temporal para almacenar la base de datos
        self._tmp_path = tempfile.NamedTemporaryFile(prefix='prowler-list-')
        self.db_name = self._tmp_path.name
        self.conn = sqlite3.connect(self.db_name)
        self.cache_size = cache_size or DEFAULT_CACHE_SIZE
        self._configure_cache()
        self._create_table()

    def _configure_cache(self):
        with self.conn:
            self.conn.execute(f'PRAGMA cache_size = {-self.cache_size}')
            self.conn.execute('PRAGMA journal_mode = WAL')

    def _create_table(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS list_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value BLOB
                )
            ''')

    def append(self, item):
        with self.conn:
            self.conn.execute('INSERT INTO list_items (value) VALUES (?)', (dill.dumps(item),))

    def extend(self, items):
        with self.conn:
            # The purpose of this SQLite approach is to reduce the memory usage of the application, so we prefer to iterate over the items
            # and insert them one by one, than to insert them all at once.
            for item in items:
                self.conn.execute('INSERT INTO list_items (value) VALUES (?)', (dill.dumps(item),))

    def __getitem__(self, index):
        cursor = self.conn.execute('SELECT value FROM list_items ORDER BY id LIMIT 1 OFFSET ?', (index,))
        row = cursor.fetchone()
        if row:
            return dill.loads(row[0])
        else:
            raise IndexError('list index out of range')

    def __setitem__(self, index, value):
        cursor = self.conn.execute('SELECT id FROM list_items ORDER BY id LIMIT 1 OFFSET ?', (index,))
        row = cursor.fetchone()
        if row:
            self.conn.execute('UPDATE list_items SET value = ? WHERE id = ?', (dill.dumps(value), row[0]))
        else:
            raise IndexError('list index out of range')

    def __len__(self):
        cursor = self.conn.execute('SELECT COUNT(*) FROM list_items')
        return cursor.fetchone()[0]

    def __delitem__(self, index):
        cursor = self.conn.execute('SELECT id FROM list_items ORDER BY id LIMIT 1 OFFSET ?', (index,))
        row = cursor.fetchone()
        if row:
            self.conn.execute('DELETE FROM list_items WHERE id = ?', (row[0],))
            self._reindex_table()
        else:
            raise IndexError('list index out of range')

    def _reindex_table(self):
        # Execute VACUUM outside of a transaction
        self.conn.isolation_level = None
        self.conn.execute('VACUUM')
        self.conn.isolation_level = ''  # Reset to default

    def __iter__(self):
        cursor = self.conn.execute('SELECT value FROM list_items ORDER BY id')
        for row in cursor:
            yield dill.loads(row[0])

    def close(self):
        self.conn.close()

    def __del__(self):
        self.close()
        self._tmp_path.close()

    def __add__(self, other):
        if isinstance(other, SQLiteList):
            new_list = SQLiteList()
            for item in self:
                new_list.append(item)
            for item in other:
                new_list.append(item)
            return new_list
        elif isinstance(other, list):
            new_list = SQLiteList()
            for item in self:
                new_list.append(item)
            for item in other:
                new_list.append(item)
            return new_list
        else:
            raise TypeError("Unsupported operand type(s) for +: 'SQLiteList' and '{}'".format(type(other).__name__))

    def __iadd__(self, other):
        if isinstance(other, (SQLiteList, list)):
            for item in other:
                self.append(item)
            return self
        else:
            raise TypeError("Unsupported operand type(s) for +=: 'SQLiteList' and '{}'".format(type(other).__name__))

    def __contains__(self, item):
        cursor = self.conn.execute('SELECT 1 FROM list_items WHERE value = ?', (dill.dumps(item),))
        return cursor.fetchone() is not None


__all__ = ('SQLiteList', 'SQLiteDict')
