import abc

from collections.abc import KeysView, ValuesView, ItemsView
from typing import Iterator


# -------------------------------------------------------------------------
# Shared interface for list and dict structures
# -------------------------------------------------------------------------
class _InterfaceGenericStructure(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __create_table__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def __iter__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def __contains__(self, key) -> bool:
        """Check if the key is in the structure."""
        raise NotImplementedError

    @abc.abstractmethod
    def __getitem__(self, item):
        raise NotImplementedError

    @abc.abstractmethod
    def __setitem__(self, key, value):
        raise NotImplementedError

    @abc.abstractmethod
    def __delitem__(self, key):
        raise NotImplementedError

    @abc.abstractmethod
    def __len__(self):
        return NotImplementedError

    @abc.abstractmethod
    def __del__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def close(self):
        raise NotImplementedError

    @abc.abstractmethod
    def clear(self):
        raise NotImplementedError


# -------------------------------------------------------------------------
# Interface Classes for Dict Structure
# -------------------------------------------------------------------------
class InterfaceSQLiteKeysView(KeysView, metaclass=abc.ABCMeta):
    """
    This class is used to define the interface for the SQLiteKeysView class.

    It defines the methods and properties that the SQLiteKeysView class must implement.
    """

    @abc.abstractmethod
    def __init__(self, sqlitedict):
        raise NotImplemented()

    @abc.abstractmethod
    def __iter__(self) -> Iterator:
        raise NotImplemented()

    @abc.abstractmethod
    def __contains__(self, key) -> bool:
        raise NotImplemented()

    @abc.abstractmethod
    def __len__(self) -> int:
        raise NotImplemented()

    @abc.abstractmethod
    def __reversed__(self) -> Iterator:
        raise NotImplemented()


class InterfaceSQLiteValuesView(ValuesView, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, sqlitedict):
        raise NotImplemented()

    @abc.abstractmethod
    def __iter__(self) -> Iterator:
        raise NotImplemented()

    @abc.abstractmethod
    def __contains__(self, value) -> bool:
        raise NotImplemented()

    @abc.abstractmethod
    def __len__(self) -> int:
        raise NotImplemented()

    @abc.abstractmethod
    def __reversed__(self) -> Iterator:
        raise NotImplemented()


class InterfaceSQLiteItemsView(ItemsView, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, sqlitedict):
        raise NotImplemented()

    @abc.abstractmethod
    def __iter__(self) -> Iterator:
        raise NotImplemented()

    @abc.abstractmethod
    def __contains__(self, item) -> bool:
        raise NotImplemented()

    @abc.abstractmethod
    def __len__(self) -> int:
        raise NotImplemented()

    @abc.abstractmethod
    def __reversed__(self) -> Iterator:
        raise NotImplemented()


class InterfaceDict(_InterfaceGenericStructure):

    @abc.abstractmethod
    def keys(self):
        raise NotImplementedError

    @abc.abstractmethod
    def values(self):
        raise NotImplementedError

    @abc.abstractmethod
    def items(self):
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, key, default=None):
        raise NotImplementedError

    @abc.abstractmethod
    def pop(self, key, default=None):
        raise NotImplementedError

    @abc.abstractmethod
    def popitem(self):
        raise NotImplementedError

    @abc.abstractmethod
    def setdefault(self, key, default=None):
        raise NotImplementedError

    @abc.abstractmethod
    def update(self, other):
        raise NotImplementedError

    @abc.abstractmethod
    def fromkeys(cls, keys, value=None):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError


# -------------------------------------------------------------------------
# Interface Classes for List Structure
# -------------------------------------------------------------------------
class InterfaceList(_InterfaceGenericStructure):

    @abc.abstractmethod
    def __reindex_table__(self, last_element_modified: int):
        raise NotImplementedError

    @abc.abstractmethod
    def append(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def extend(self, iterable):
        raise NotImplementedError

    @abc.abstractmethod
    def insert(self, index, value):
        raise NotImplementedError

    @abc.abstractmethod
    def remove(self, value):
        raise NotImplementedError

    @abc.abstractmethod
    def pop(self, index=-1):
        raise NotImplementedError

    @abc.abstractmethod
    def __add__(self, other):
        raise NotImplementedError

    @abc.abstractmethod
    def __iadd__(self, other):
        raise NotImplementedError
