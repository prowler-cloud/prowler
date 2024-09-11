import os

from .sqlite import SQLiteDict, SQLiteList

default_list = SQLiteList


def mklist() -> list:
    """
    Create a new list with the given name and data.
    """
    # TODO: do we need to verify this each time? It should be done during startup
    prowler_db_connection = os.environ.get("PROWLER_DB_CONNECTION", "sqlite://")

    try:
        prowler_db_cache_size = int(os.environ.get("PROWLER_DB_CACHE_SIZE", 2000))
    except ValueError:
        prowler_db_cache_size = 2000

    # SQLite 3 - Default.
    if not prowler_db_connection:
        return SQLiteList(cache_size=prowler_db_cache_size)

    # In-memory.
    # TODO: review if we allow having a DB connection in the environment variable
    if prowler_db_connection.startswith("memory://"):
        return list()

    # SQLite 3 - Default.
    elif prowler_db_connection.startswith("sqlite://"):
        return SQLiteList(cache_size=prowler_db_cache_size)

    else:
        raise ValueError(f"Unsupported database connection: {prowler_db_connection}")


def mkdict() -> dict:
    """
    Create a new dictionary with the given name and data.
    """
    # TODO: do we need to verify this each time? It should be done during startup
    prowler_db_connection = os.environ.get("PROWLER_DB_CONNECTION", "sqlite://")

    try:
        prowler_db_cache_size = int(os.environ.get("PROWLER_DB_CACHE_SIZE", 2000))
    except ValueError:
        prowler_db_cache_size = 2000

    # SQLite 3 - Default.
    if not prowler_db_connection:
        return SQLiteDict(cache_size=prowler_db_cache_size)

    # In-memory.
    if prowler_db_connection.startswith("memory://"):
        return dict()

    # SQLite 3 - Default.
    elif prowler_db_connection.startswith("sqlite://"):
        return SQLiteDict(cache_size=prowler_db_cache_size)

    else:
        raise ValueError(f"Unsupported database connection: {prowler_db_connection}")


__all__ = ("mklist", "mkdict")
