from api.attack_paths.queries.types import AttackPathsQueryDefinition
from api.attack_paths.queries.aws import AWS_QUERIES


# Query definitions organized by provider
_QUERY_DEFINITIONS: dict[str, list[AttackPathsQueryDefinition]] = {
    "aws": AWS_QUERIES,
}

# Flat lookup by query ID for O(1) access
_QUERIES_BY_ID: dict[str, AttackPathsQueryDefinition] = {
    definition.id: definition
    for definitions in _QUERY_DEFINITIONS.values()
    for definition in definitions
}


def get_queries_for_provider(provider: str) -> list[AttackPathsQueryDefinition]:
    """Get all attack path queries for a specific provider."""
    return _QUERY_DEFINITIONS.get(provider, [])


def get_query_by_id(query_id: str) -> AttackPathsQueryDefinition | None:
    """Get a specific attack path query by its ID."""
    return _QUERIES_BY_ID.get(query_id)
