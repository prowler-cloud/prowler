"""Shared helpers for building models from Prowler API responses.

Stateless utilities used by the models' ``from_api_response()`` factory methods
to read the JSON:API document structure (relationships, linkage, etc.). Keeping
them here leaves ``base.py`` focused on the base model/mixin and gives these
response-parsing helpers a single, discoverable home.
"""

from typing import Any


def extract_relationship_ids(
    relationships: dict[str, Any], relationship_name: str
) -> list[str]:
    """Extract related resource IDs from a JSON:API relationship.

    Handles both to-one (``data`` is an object) and to-many (``data`` is a list)
    relationships, returning a flat list of IDs in either case. Missing or empty
    relationships yield an empty list.

    Args:
        relationships: The ``relationships`` object from a JSON:API resource
        relationship_name: The relationship key to read (e.g. ``"roles"``)

    Returns:
        List of related resource IDs (empty if the relationship is absent/empty)
    """
    data = relationships.get(relationship_name, {}).get("data")
    if not data:
        return []
    if isinstance(data, list):
        return [item["id"] for item in data if item and item.get("id")]
    # to-one relationship
    return [data["id"]] if data.get("id") else []
