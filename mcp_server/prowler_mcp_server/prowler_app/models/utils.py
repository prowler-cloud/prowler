"""Shared helpers for building models from Prowler API responses.

Stateless utilities used by the models' ``from_api_response()`` factory methods
to read the JSON:API document structure (relationships, linkage, etc.). Keeping
them here leaves ``base.py`` focused on the base model/mixin and gives these
response-parsing helpers a single, discoverable home.
"""

from typing import Any


def extract_relationship_ids(
    relationships: dict[str, Any], relationship_name: str
) -> list[str] | None:
    """Extract related resource IDs from a JSON:API relationship.

    Handles both to-one (``data`` is an object) and to-many (``data`` is a list)
    relationships, returning a flat list of IDs in either case.

    The absent and present-but-empty cases are deliberately distinguished so
    callers can tell "the relationship was not part of this document" from "the
    relationship is genuinely empty":

    - Relationship key absent → ``None`` (unknown; the serializer did not expose
      it, e.g. a role included via ``?include=roles`` carries no ``users``).
    - Relationship key present but with no members → ``[]`` (explicitly none).

    Args:
        relationships: The ``relationships`` object from a JSON:API resource
        relationship_name: The relationship key to read (e.g. ``"roles"``)

    Returns:
        List of related resource IDs, ``[]`` if the relationship is present but
        empty, or ``None`` if the relationship is absent from the document.
    """
    relationship = relationships.get(relationship_name)
    if relationship is None:
        return None
    data = relationship.get("data")
    if not data:
        return []
    if isinstance(data, list):
        return [item["id"] for item in data if item and item.get("id")]
    # to-one relationship
    return [data["id"]] if data.get("id") else []
