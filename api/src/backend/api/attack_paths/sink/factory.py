"""Sink backend factory and process-wide handle cache.

Picks the active backend from `settings.ATTACK_PATHS_SINK_DATABASE` at first
use, holds the active backend plus any secondary backends needed to serve
scans written under the previous configuration, and tears them all down on
process shutdown. Imported via `from api.attack_paths import sink as
sink_module`.
"""
from __future__ import annotations

import threading
from enum import StrEnum, auto
from typing import TYPE_CHECKING

from django.conf import settings

from api.attack_paths.sink.base import SinkDatabase

if TYPE_CHECKING:
    from api.models import AttackPathsScan


# Backend names

class SinkBackend(StrEnum):
    NEO4J = auto()
    NEPTUNE = auto()


# Backend cache

_backend: SinkDatabase | None = None
_secondary_backends: dict[SinkBackend, SinkDatabase] = {}
_lock = threading.Lock()


def _resolve_setting() -> SinkBackend:
    raw = getattr(settings, "ATTACK_PATHS_SINK_DATABASE", SinkBackend.NEO4J).lower()
    try:
        return SinkBackend(raw)
    except ValueError:
        valid = sorted(b.value for b in SinkBackend)
        raise RuntimeError(
            f"ATTACK_PATHS_SINK_DATABASE must be one of {valid}; got {raw!r}"
        )


def _build_backend(name: SinkBackend) -> SinkDatabase:
    if name is SinkBackend.NEO4J:
        from api.attack_paths.sink.neo4j import Neo4jSink

        return Neo4jSink()
    if name is SinkBackend.NEPTUNE:
        from api.attack_paths.sink.neptune import NeptuneSink

        return NeptuneSink()
    raise RuntimeError(f"Unknown sink backend {name!r}")


# Lifecycle

def init(name: SinkBackend | str | None = None) -> SinkDatabase:
    """Initialize the configured sink backend. Idempotent."""
    global _backend
    if _backend is not None:
        return _backend
    with _lock:
        if _backend is None:
            resolved = SinkBackend(name) if name else _resolve_setting()
            backend = _build_backend(resolved)
            backend.init()
            _backend = backend
    return _backend


def close() -> None:
    """Close the active backend and every cached secondary backend."""
    global _backend
    with _lock:
        backends = [b for b in (_backend, *_secondary_backends.values()) if b is not None]
        _backend = None
        _secondary_backends.clear()
    for backend in backends:
        try:
            backend.close()
        except Exception:  # pragma: no cover - best-effort
            pass


def get_backend() -> SinkDatabase:
    """Return the active sink. Initializes on first call."""
    return init()


# Per-scan routing

def get_backend_for_scan(scan: "AttackPathsScan") -> SinkDatabase:
    """Route reads by the scan row's recorded sink, not by current settings.

    Scans written under Neo4j remain queryable via the Neo4j sink even when the
    process was later reconfigured to Neptune.

    # TODO: drop after Neptune cutover
    """
    if getattr(scan, "is_neptune", False):
        if _resolve_setting() is not SinkBackend.NEPTUNE:
            return _build_backend_cached(SinkBackend.NEPTUNE)
        return get_backend()

    if _resolve_setting() is SinkBackend.NEPTUNE:
        return _build_backend_cached(SinkBackend.NEO4J)
    return get_backend()


def _build_backend_cached(name: SinkBackend) -> SinkDatabase:
    # TODO: drop after Neptune cutover
    # Needed only during cutover to serve Neo4j-written scans from a Neptune-
    # configured API pod (and vice versa). Once every scan is on Neptune,
    # `get_backend_for_scan` becomes a one-liner returning `get_backend()`.
    if name in _secondary_backends:
        return _secondary_backends[name]
    with _lock:
        if name not in _secondary_backends:
            backend = _build_backend(name)
            backend.init()
            _secondary_backends[name] = backend
    return _secondary_backends[name]
