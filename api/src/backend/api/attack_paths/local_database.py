"""
Local embedded graph database for temporary scan databases.

Mirrors `database.py`'s public API (`get_session`, `create_database`, `drop_database`).
Uses Grafeo as the embedded graph engine. Grafeo is an implementation detail;
if it gets swapped for something else, only this file changes.
"""

import logging
import os
import shutil
import tempfile

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, cast

import neo4j

from grafeo import GrafeoDB

logger = logging.getLogger(__name__)


# Result / Record wrappers


class _Record:
    """Wraps a dict to behave like a `neo4j.Record`."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def data(self) -> dict[str, Any]:
        return self._data

    def value(self) -> Any:
        return next(iter(self._data.values())) if self._data else None

    def values(self) -> tuple:
        return tuple(self._data.values())

    def keys(self) -> list[str]:
        return list(self._data.keys())


class _Result:
    """Wraps Grafeo query results to satisfy `GraphResult` protocol."""

    def __init__(self, records: list[_Record]):
        self._records = records

    def __iter__(self) -> Iterator[_Record]:
        return iter(self._records)

    def single(self) -> _Record | None:
        return self._records[0] if self._records else None

    def values(self) -> list[tuple]:
        return [r.values() for r in self._records]

    def consume(self) -> None:
        pass


# Session adapter


class _Session:
    """
    Wraps GrafeoDB to behave like a `neo4j.Session`.

    All Cypher passes through to `execute_cypher()`.

    Cartography calls `session.execute_write(tx_func, args, kwargs)` where
    `tx_func` receives the session as first arg and calls `.run()` on it.
    That's why `execute_write` just calls `fn(self, ...)`.
    """

    def __init__(self, db: GrafeoDB):
        self._db = db

    def run(self, query: str, parameters: dict[str, Any] | None = None, **kwargs: Any) -> neo4j.Result:
        parameters = {**(parameters or {}), **kwargs}
        try:
            raw = list(self._db.execute_cypher(query, parameters))
        except RuntimeError:
            logger.error("Grafeo query failed:\n%s\nParameters: %s", query, list(parameters.keys()))
            raise
        records = [_Record(row) for row in raw]
        return cast(neo4j.Result, _Result(records))

    def execute_write(self, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        return fn(self, *args, **kwargs)

    def execute_read(self, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        return fn(self, *args, **kwargs)

    def close(self) -> None:
        pass


# Public API (mirrors database.py)


@contextmanager
def get_session(database_name: str) -> Iterator[neo4j.Session]:
    """Open a session to a local embedded graph database.

    Returns a neo4j.Session-typed handle so callers (including Cartography,
    which expects neo4j.Session) can use it directly without casting.
    """
    path = _resolve_path(database_name)
    db = GrafeoDB(path)
    session = _Session(db)
    try:
        yield cast(neo4j.Session, session)
    finally:
        session.close()


def create_database(database_name: str) -> None:
    """Create an empty local graph database."""
    path = _resolve_path(database_name)
    GrafeoDB(path)


def drop_database(database_name: str) -> None:
    """Delete a local graph database."""
    path = _resolve_path(database_name)
    target = Path(path)
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


# Internal


def _resolve_path(database_name: str) -> str:
    return os.path.join(tempfile.gettempdir(), "prowler-attack-paths", database_name)
