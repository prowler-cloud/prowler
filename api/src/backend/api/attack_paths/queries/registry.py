from api.attack_paths.queries.aws import AWS_QUERIES

# TODO: drop after Neptune cutover
from api.attack_paths.queries.aws_deprecated import AWS_DEPRECATED_QUERIES
from api.attack_paths.queries.types import AttackPathsQueryDefinition


# Query definitions for scans synced with the current schema.
_QUERY_DEFINITIONS: dict[str, list[AttackPathsQueryDefinition]] = {
    "aws": AWS_QUERIES,
}

_QUERIES_BY_ID: dict[str, AttackPathsQueryDefinition] = {
    definition.id: definition
    for definitions in _QUERY_DEFINITIONS.values()
    for definition in definitions
}


# TODO: drop after Neptune cutover
#
# Query definitions for pre-cutover scans (`AttackPathsScan.is_migrated=False`)
# whose graph data was written under the previous schema. Both maps expose the
# same query IDs so the API contract is identical regardless of which set is
# routed to.
_DEPRECATED_QUERY_DEFINITIONS: dict[str, list[AttackPathsQueryDefinition]] = {
    "aws": AWS_DEPRECATED_QUERIES,
}

_DEPRECATED_QUERIES_BY_ID: dict[str, AttackPathsQueryDefinition] = {
    definition.id: definition
    for definitions in _DEPRECATED_QUERY_DEFINITIONS.values()
    for definition in definitions
}


def get_queries_for_provider(
    provider: str,
    is_migrated: bool = True,
) -> list[AttackPathsQueryDefinition]:
    """Get all attack path queries for a provider.

    `is_migrated` selects the catalog: True for scans synced with the current
    schema, False for pre-cutover scans still in the legacy Neo4j tenant DB.
    # TODO: drop the `is_migrated` parameter after Neptune cutover
    """
    catalog = _QUERY_DEFINITIONS if is_migrated else _DEPRECATED_QUERY_DEFINITIONS
    return catalog.get(provider, [])


def get_query_by_id(
    query_id: str,
    is_migrated: bool = True,
) -> AttackPathsQueryDefinition | None:
    """Get a specific attack path query by ID.

    `is_migrated` selects the catalog (see `get_queries_for_provider`).
    # TODO: drop the `is_migrated` parameter after Neptune cutover
    """
    by_id = _QUERIES_BY_ID if is_migrated else _DEPRECATED_QUERIES_BY_ID
    return by_id.get(query_id)
