"""Protocol every sink backend must implement."""

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

    def verify_connectivity(self) -> None:
        """Raise if the backend the API read path uses is unreachable.

        Neo4j verifies its single driver. Neptune verifies the reader
        driver (the endpoint the API serves reads from); on single-endpoint
        clusters the reader aliases the writer, so that path is covered too.
        Used by the readiness probe; must not block longer than the caller's
        probe budget.
        """
        ...

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

    def ensure_sync_indexes(self, database: str) -> None:
        """Create any index needed for the sync write path.

        Called once at the start of each provider sync; must be idempotent.
        Neo4j creates a `_provider_element_id` index on `_ProviderResource`;
        Neptune is a no-op (its `~id` lookup needs no index).
        """
        ...

    def write_nodes(
        self,
        database: str,
        labels: str,
        rows: list[dict[str, Any]],
    ) -> None:
        """Upsert a batch of nodes into the sink.

        `labels` is a pre-rendered Cypher label string ready to drop after
        the node variable (e.g. `` `AWSUser`:`_ProviderResource`:`_Tenant_x` ``).
        Each row carries `provider_element_id` and `props`.
        """
        ...

    def write_relationships(
        self,
        database: str,
        rel_type: str,
        provider_id: str,
        rows: list[dict[str, Any]],
    ) -> None:
        """Upsert a batch of relationships into the sink.

        Each row carries `start_element_id`, `end_element_id`,
        `provider_element_id` and `props`. `rel_type` is the relationship
        type (already a valid Cypher identifier).
        """
        ...
