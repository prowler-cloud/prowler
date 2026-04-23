"""Operational helpers for the legacy Neo4j tenant DBs.

Used by the ``list_neo4j_tenant_dbs`` management command to help operators
decide when phase 2 of the Neptune migration can ship.

# TODO: Drop after Neptune migration is finished
"""
from __future__ import annotations


def list_neo4j_tenant_databases() -> list[str]:
    """Return the names of ``db-tenant-*`` databases present on Neo4j.

    Runs against the Neo4j sink driver directly, so it works regardless of
    the currently active sink backend.
    """
    from api.attack_paths.sink.neo4j import Neo4jSink

    sink = Neo4jSink()
    try:
        with sink.get_session() as session:
            result = session.run("SHOW DATABASES YIELD name RETURN name")
            return sorted(
                record["name"]
                for record in result
                if record["name"].startswith("db-tenant-")
            )
    finally:
        try:
            sink.close()
        except Exception:  # pragma: no cover
            pass
