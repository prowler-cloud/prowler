import sqlite3

from functools import partial
from typing import Iterator

import dill

from .wrapper import Wrapper
from .interfaces import GenericSQLiteStructure
from ..interfaces import InterfaceDict, InterfaceSQLiteKeysView, InterfaceSQLiteItemsView, InterfaceSQLiteValuesView


class SharedDictView:

    def __len__(self):
        cursor = self.sqlitedict.conn.execute("SELECT COUNT(*) FROM structure_items")
        return cursor.fetchone()[0]


class SQLiteKeysView(SharedDictView, InterfaceSQLiteKeysView):

    def __init__(self, sqlitedict: "SQLiteDict"):
        self.sqlitedict = sqlitedict

    def __iter__(self) -> Iterator[str]:
        cursor = self.sqlitedict.conn.execute("SELECT key FROM structure_items")
        for row in cursor:
            yield row[0]

    def __contains__(self, key) -> bool:
        with self.sqlitedict.conn:
            cursor = self.sqlitedict.conn.execute("SELECT 1 FROM structure_items WHERE key = ?", (key,))
            return cursor.fetchone() is not None

    def __reversed__(self) -> Iterator:
        cursor = self.sqlitedict.conn.execute("SELECT key FROM structure_items ORDER BY rowid DESC")
        for row in cursor:
            yield row[0]


class SQLiteValuesView(SharedDictView, InterfaceSQLiteValuesView):
    """
    A custom view for values in a SQLite-backed dictionary. This class
    provides an interface to access and manipulate the values stored in
    a SQLite database as if they were part of a standard dictionary.
    """

    def __init__(self, sqlitedict: "SQLiteDict"):
        self.sqlitedict = sqlitedict

    def __cross_cursor__(self, cursor):
        for row in cursor:

            loaded_value = dill.loads(row[0])

            if loaded_value is None:
                yield None

            else:
                yield Wrapper(parent_reference=loaded_value, real_obj=loaded_value, callback=self.sqlitedict.__make_update_function__(row[1]))

    def __iter__(self):
        cursor = self.sqlitedict.conn.execute("SELECT value, key FROM structure_items")

        yield from self.__cross_cursor__(cursor)

    def __reversed__(self):
        cursor = self.sqlitedict.conn.execute("SELECT value, key FROM structure_items ORDER BY rowid DESC")

        yield from self.__cross_cursor__(cursor)

    def __contains__(self, value):
        for val in self:
            if val == value:
                return True
        return False


class SQLiteItemsView(SharedDictView, InterfaceSQLiteItemsView):
    def __init__(self, sqlitedict: "SQLiteDict", proxy=True):
        self.sqlitedict = sqlitedict
        self.proxy = proxy

    def __cross_cursor__(self, cursor):

        for row in cursor:
            if self.proxy:
                loaded_value = dill.loads(row[1])

                if loaded_value is None:
                    yield row[0], None

                else:
                    yield row[0], Wrapper(
                        parent_reference=loaded_value, real_obj=loaded_value, callback=self.sqlitedict.__make_update_function__(row[0])
                    )

            else:
                yield row[0], dill.loads(row[1])

    def __iter__(self):
        cursor = self.sqlitedict.conn.execute("SELECT key, value FROM structure_items")
        yield from self.__cross_cursor__(cursor)

    def __reversed__(self):
        cursor = self.sqlitedict.conn.execute("SELECT key, value FROM structure_items ORDER BY rowid DESC")
        yield from self.__cross_cursor__(cursor)

    def __contains__(self, item):
        key, value = item
        with self.sqlitedict.conn:
            cursor = self.sqlitedict.conn.execute("SELECT value FROM structure_items WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return dill.loads(row[0]) == value
        return False


class SQLiteDict(GenericSQLiteStructure, InterfaceDict):
    """
    A dictionary-like object backed by an SQLite database.
    """

    def __create_table__(self):
        """
        Creates a table named 'dict_items' in the SQLite database if it doesn't already exist.
        The table has two columns: 'key' of type TEXT (primary key) and 'value' of type BLOB.
        """

        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS structure_items (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            """
            )

    def __update_item__(self, key, value):
        with self.conn:
            found = self.conn.execute(
                "UPDATE structure_items SET value = ? WHERE key = ?",
                (dill.dumps(value), key),
            )

            if found.rowcount == 0:
                # If the item is not found, raise a ValueError, insert them
                ret = self.conn.execute(
                    "INSERT INTO structure_items (key, value) VALUES (?, ?)",
                    (key, dill.dumps(value)),
                )

                if ret.rowcount == 0:
                    raise ValueError("Item not found")

    def __make_update_function__(self, key):
        fn = partial(self.__update_item__, key)

        return fn

    def __iter__(self):
        with self.conn:
            cursor = self.conn.execute("SELECT key FROM structure_items")
            for row in cursor:

                deserialized_value = dill.loads(row[0])

                if deserialized_value is None:
                    yield None

                else:
                    yield Wrapper(
                        parent_reference=deserialized_value, real_obj=deserialized_value, callback=self.__make_update_function__(row[1])
                    )

    def __getitem__(self, key):
        with self.conn:
            cursor = self.conn.execute(
                "SELECT value FROM structure_items WHERE key = ?", (key,)
            )
            row = cursor.fetchone()

            if row:
                deserialized_value = dill.loads(row[0])

                if deserialized_value is None:
                    return None

                else:
                    return Wrapper(
                        parent_reference=deserialized_value, real_obj=deserialized_value, callback=self.__make_update_function__(key)
                    )

            else:
                raise KeyError(key)

    def __contains__(self, key):
        with self.conn:
            cursor = self.conn.execute("SELECT 1 FROM structure_items WHERE key = ?", (key,))
            return cursor.fetchone() is not None

    def __setitem__(self, key, value):
        self.__update_item__(key, value)

    def __len__(self):
        cursor = self.conn.execute("SELECT COUNT(*) FROM structure_items")
        return cursor.fetchone()[0]

    def __delitem__(self, key):
        with self.conn:
            cursor = self.conn.execute("DELETE FROM structure_items WHERE key = ?", (key,))
            if cursor.rowcount == 0:
                raise KeyError(f"Key {key} not found")

    def items(self):
        return SQLiteItemsView(self)

    def keys(self):
        return SQLiteKeysView(self)

    def values(self):
        return SQLiteValuesView(self)

    def pop(self, key, default=None):
        try:
            with self.conn:
                cursor = self.conn.execute(
                    "SELECT value FROM structure_items WHERE key = ?", (key,)
                )
                row = cursor.fetchone()
                if row:
                    value = dill.loads(row[0])
                    self.conn.execute("DELETE FROM structure_items WHERE key = ?", (key,))
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
            cursor = self.conn.execute("SELECT key, value FROM structure_items LIMIT 1")
            row = cursor.fetchone()
            if row:
                key, value = row[0], dill.loads(row[1])
                self.conn.execute("DELETE FROM structure_items WHERE key = ?", (key,))
                return key, value
            raise KeyError("Dictionary is empty")

    def update(self, other=None, **kwargs):
        if other is not None:
            if hasattr(other, "items"):
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
        items = SQLiteItemsView(self, proxy=False)
        for key, value in items:
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

    def __reduce_ex__(self, protocol):
        return type(self), (), self.__dict__
