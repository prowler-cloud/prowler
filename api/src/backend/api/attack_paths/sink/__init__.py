"""
Attack-paths sink database layer.

The sink is the persistent store where attack-paths graphs live after a scan
finishes. Currently selectable between Neo4j (OSS / local dev default) and
AWS Neptune (hosted dev/staging/prod). Backend is picked by the
``ATTACK_PATHS_SINK_DATABASE`` setting at process init.
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from django.conf import settings

from api.attack_paths.sink.base import SinkDatabase

if TYPE_CHECKING:
    from api.models import AttackPathsScan

_backend: SinkDatabase | None = None
_lock = threading.Lock()

NEO4J = "neo4j"
NEPTUNE = "neptune"
VALID_BACKENDS = {NEO4J, NEPTUNE}


def _resolve_setting() -> str:
    value = getattr(settings, "ATTACK_PATHS_SINK_DATABASE", NEO4J).lower()
    if value not in VALID_BACKENDS:
        raise RuntimeError(
            f"ATTACK_PATHS_SINK_DATABASE must be one of {sorted(VALID_BACKENDS)}; got {value!r}"
        )
    return value


def _build_backend(name: str) -> SinkDatabase:
    if name == NEO4J:
        from api.attack_paths.sink.neo4j import Neo4jSink

        return Neo4jSink()
    if name == NEPTUNE:
        from api.attack_paths.sink.neptune import NeptuneSink

        return NeptuneSink()
    raise RuntimeError(f"Unknown sink backend {name!r}")


def init(name: str | None = None) -> SinkDatabase:
    """Initialize the configured sink backend. Idempotent."""
    global _backend
    if _backend is not None:
        return _backend
    with _lock:
        if _backend is None:
            _backend = _build_backend(name or _resolve_setting())
            _backend.init()
    return _backend


def close() -> None:
    global _backend
    with _lock:
        if _backend is not None:
            try:
                _backend.close()
            finally:
                _backend = None


def get_backend() -> SinkDatabase:
    """Return the active sink. Initializes on first call."""
    return init()


def get_backend_for_scan(scan: "AttackPathsScan") -> SinkDatabase:
    """Route reads by the scan row's recorded sink, not by current settings.

    Scans written under Neo4j remain queryable via the Neo4j sink even when the
    process was later reconfigured to Neptune.

    # TODO: Drop after Neptune migration is finished
    """
    if getattr(scan, "is_neptune", False):
        if _resolve_setting() != NEPTUNE:
            # Neptune scan on a Neo4j-configured process. Try to build a Neptune
            # backend on demand; will fail loudly if NEPTUNE_* env is absent.
            return _build_backend_cached(NEPTUNE)
        return get_backend()

    if _resolve_setting() == NEPTUNE:
        # Neo4j scan on a Neptune-configured process (rare — pre-migration row).
        return _build_backend_cached(NEO4J)
    return get_backend()


_secondary_backends: dict[str, SinkDatabase] = {}


def _build_backend_cached(name: str) -> SinkDatabase:
    # TODO: Drop after Neptune migration is finished
    # Needed only in phase 1 to serve Neo4j-written scans from a Neptune-configured
    # API pod (and vice versa). In phase 2, get_backend_for_scan() becomes a
    # one-liner returning get_backend().
    if name in _secondary_backends:
        return _secondary_backends[name]
    with _lock:
        if name not in _secondary_backends:
            backend = _build_backend(name)
            backend.init()
            _secondary_backends[name] = backend
    return _secondary_backends[name]
