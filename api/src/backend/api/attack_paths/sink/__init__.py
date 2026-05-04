"""Attack-paths sink database layer.

The sink is the persistent store where attack-paths graphs live after a scan
finishes. Currently selectable between Neo4j (OSS / local dev default) and
AWS Neptune (hosted dev/staging/prod). Backend is picked by the
`ATTACK_PATHS_SINK_DATABASE` setting at process init.

This package exposes the public factory API; the implementation lives in
`api.attack_paths.sink.factory`.
"""
from __future__ import annotations

from api.attack_paths.sink.factory import (
    SinkBackend,
    close,
    get_backend,
    get_backend_for_scan,
    init,
)

__all__ = [
    "SinkBackend",
    "close",
    "get_backend",
    "get_backend_for_scan",
    "init",
]
