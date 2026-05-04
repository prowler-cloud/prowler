"""Protocol every sink backend must implement."""
from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Protocol

import neo4j


class SinkDatabase(Protocol):
    """Contract for the persistent attack-paths graph store.

    The `database` argument is an opaque identifier passed through from the
    legacy `database.py` API surface. On Neo4j it is the per-tenant database
    name (e.g. `db-tenant-{uuid}`). On Neptune it is ignored (the cluster
    has a single graph, and isolation is label-based).
    """

    def init(self) -> None: ...

    def close(self) -> None: ...

    def get_session(
        self,
        database: str | None = None,
        default_access_mode: str | None = None,
    ) -> AbstractContextManager: ...

    def execute_read_query(
        self,
        database: str,
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> neo4j.graph.Graph: ...

    def create_database(self, database: str) -> None: ...

    def drop_database(self, database: str) -> None: ...

    def drop_subgraph(self, database: str, provider_id: str) -> int: ...

    def has_provider_data(self, database: str, provider_id: str) -> bool: ...

    def clear_cache(self, database: str) -> None: ...
