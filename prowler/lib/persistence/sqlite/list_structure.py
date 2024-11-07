from functools import partial

import dill

from .wrapper import Wrapper
from ..interfaces import InterfaceList
from .interfaces import GenericSQLiteStructure


# TODO: document class and methods
class SQLiteList(GenericSQLiteStructure, InterfaceList):

    def __create_table__(self):
        with self.conn:
            #
            # An VERY IMPORTANT NOTE about the table 'id' column:
            #
            # Due the Python lists start at index 0, we need to add 1 to the index to store it in the database.
            # SQLite does not support the AUTOINCREMENT starting at 0, so we need to start at 1.
            #
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS structure_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value BLOB
                )
            """
            )

    def __update_item__(self, item_id, item):
        with self.conn:
            found = self.conn.execute(
                "UPDATE structure_items SET value = ? WHERE id = ?",
                (dill.dumps(item), item_id),
            )

            if found.rowcount == 0:
                raise ValueError("Item not found")

    def __make_update_function__(self, item_id):
        fn = partial(self.__update_item__, item_id)

        return fn

    def insert(self, index, value):
        with self.conn:
            # First: check if the index is valid
            cursor = self.conn.execute(
                "SELECT id FROM structure_items WHERE id = ? ORDER BY id", (index + 1,)
            )
            row = cursor.fetchone()
            if row:

                # Second: insert the new item in the correct position
                self.conn.execute(
                    "INSERT INTO structure_items (value) VALUES (?)", (dill.dumps(value),)
                )

            else:
                raise IndexError("list index out of range")

    def remove(self, value):
        with self.conn:
            # First: check if the item exists
            cursor = self.conn.execute(
                "SELECT id FROM structure_items WHERE value = ?", (dill.dumps(value),)
            )
            row = cursor.fetchone()
            if row:
                # Second: remove the item
                self.conn.execute("DELETE FROM structure_items WHERE id = ?", (row[0],))
                self.__reindex_table__(row[0])

    def pop(self, index=-1):
        with self.conn:
            # First: check if the index is valid
            cursor = self.conn.execute(
                "SELECT value, id FROM structure_items WHERE id = ? ORDER BY id", (index + 1,)
            )
            row = cursor.fetchone()
            if row:

                # Second: remove the item
                self.conn.execute("DELETE FROM structure_items WHERE id = ?", (row[1],))
                self.__reindex_table__(row[1])

                # Third: return the item
                return dill.loads(row[0])

            else:
                raise IndexError("pop index out of range")

    def append(self, item):
        with self.conn:
            # TODO: review warning
            try:
                self.conn.execute(
                    "INSERT INTO structure_items (value) VALUES (?)", (dill.dumps(item),)

                )
            except TypeError as error:
                print(error)
                raise

    def extend(self, items):
        with self.conn:
            # The purpose of this SQLite approach is to reduce the memory usage of the application, so we prefer to iterate over the items
            # and insert them one by one, than to insert them all at once.
            for item in items:
                self.append(item)

    def __getitem__(self, index):
        """This is called when the list is accessed with the square brackets notation."""
        cursor = self.conn.execute(
            "SELECT value, id FROM structure_items WHERE id = ? ORDER BY id", (index + 1,)
        )
        row = cursor.fetchone()
        if row:

            deserialized_value = dill.loads(row[0])

            if deserialized_value is None:
                return None

            else:
                return Wrapper(
                    parent_reference=deserialized_value, real_obj=deserialized_value, callback=self.__make_update_function__(row[1])
                )

        else:
            raise IndexError("list index out of range")

    def __setitem__(self, index, value):
        """This is called when the list is accessed with the square brackets notation and an assignment is made."""
        with self.conn:

            cursor = self.conn.execute(
                "SELECT id FROM structure_items WHERE id = ? ORDER BY id", (index + 1,)
            )
            row = cursor.fetchone()
            if row:
                self.__update_item__(row[0], value)

            else:
                raise IndexError("list index out of range")

    def __delitem__(self, index):
        """This is called when the list is accessed with the square brackets notation and an item is deleted."""
        cursor = self.conn.execute(
            "SELECT id FROM structure_items WHERE id = ? ORDER BY id", (index + 1,)
        )
        row = cursor.fetchone()
        if row:
            self.conn.execute("DELETE FROM structure_items WHERE id = ?", (row[0],))
            self.__reindex_table__(row[0])
        else:
            raise IndexError("list index out of range")

    def __iter__(self):
        cursor = self.conn.execute("SELECT value, id FROM structure_items ORDER BY id")
        for row in cursor:

            deserialized_value = dill.loads(row[0])

            if deserialized_value is None:
                yield None

            else:
                yield Wrapper(
                    parent_reference=deserialized_value, real_obj=deserialized_value, callback=self.__make_update_function__(row[1])
                )

    def __add__(self, other):
        if isinstance(other, (SQLiteList, list)):
            new_list = SQLiteList()
            new_list.extend(self)
            new_list.extend(other)
            return new_list

        raise TypeError(
            "Unsupported operand type(s) for +: 'SQLiteList' and '{}'".format(
                type(other).__name__
            )
        )

    def __iadd__(self, other):
        if isinstance(other, (SQLiteList, list)):
            self.extend(other)
            return self

        raise TypeError(
            f"Unsupported operand type(s) for +=: 'SQLiteList' and '{type(other).__name__}'"
        )

    def __contains__(self, item):
        with self.conn:
            cursor = self.conn.execute("SELECT 1 FROM structure_items WHERE value = ?", (dill.dumps(item),))
            return cursor.fetchone() is not None

    def __reindex_table__(self, last_element_modified: int):
        # We have to decrease the id of all elements that have an id greater than the last element modified
        self.conn.execute(
            "UPDATE structure_items SET id = id - 1 WHERE id > ?", (last_element_modified,)
        )

        # Execute VACUUM outside of a transaction
        self.conn.isolation_level = None
        self.conn.execute("VACUUM")
        self.conn.isolation_level = ""  # Reset to default
