import os

from .sqlite import SQLiteDict, SQLiteList

default_list = SQLiteList


def mklist() -> list:
    """
    Create a new list with the given name and data.
    """
    prowler_db_connection = os.environ.get("PROWLER_DB_CONNECTION", "memory://")

    try:
        prowler_db_cache_size = int(os.environ.get("PROWLER_DB_CACHE_SIZE", 2000))
    except ValueError:
        prowler_db_cache_size = 2000

    if not prowler_db_connection:
        return list()

    # In-memory. Default.
    # TODO: review if we allow having a DB connection in the environment variable
    if prowler_db_connection.startswith("memory://"):
        return list()

    # SQLite 3
    elif prowler_db_connection.startswith("sqlite://"):
        return SQLiteList(cache_size=prowler_db_cache_size)

    else:
        raise ValueError(f"Unsupported database connection: {prowler_db_connection}")


def mkdict() -> dict:
    """
    Create a new dictionary with the given name and data.
    """
    prowler_db_connection = os.environ.get("PROWLER_DB_CONNECTION", "memory://")
    try:
        prowler_db_cache_size = int(os.environ.get("PROWLER_DB_CACHE_SIZE", 2000))
    except ValueError:
        prowler_db_cache_size = 2000

    if not prowler_db_connection:
        return dict()

    # In-memory. Default.
    if prowler_db_connection.startswith("memory://"):
        return dict()

    # SQLite 3
    elif prowler_db_connection.startswith("sqlite://"):
        return SQLiteDict(cache_size=prowler_db_cache_size)

    else:
        raise ValueError(f"Unsupported database connection: {prowler_db_connection}")


__all__ = ("mklist", "mkdict")
