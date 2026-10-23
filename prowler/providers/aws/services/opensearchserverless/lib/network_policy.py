from typing import Optional


def resource_pattern_matches(pattern: str, collection_name: str) -> Optional[bool]:
    """Check whether a network policy resource pattern covers a collection.

    AWS documents only two pattern forms for OpenSearch Serverless network
    policies: an exact collection name (``collection/logs-prod``) and a prefix
    followed by a single trailing wildcard (``collection/logs*``,
    ``collection/*``). Any other form (uppercase letters, a wildcard in
    another position, a missing ``collection/`` prefix) has undocumented
    matching behavior, so it is reported as undetermined instead of guessed.

    Args:
        pattern: A resource pattern from a network policy rule, including
            the ``collection/`` prefix.
        collection_name: The name of an existing collection.

    Returns:
        True if the pattern covers the collection, False if it does not,
        or None if the match cannot be determined from documented behavior.
    """

    if not pattern.startswith("collection/"):
        return None

    pattern = pattern.removeprefix("collection/")

    for letra in pattern:
        if letra.isupper():
            return None

    if "*" not in pattern:
        return pattern == collection_name

    if pattern == "*":
        return True

    if pattern.count("*") == 1 and pattern.endswith("*"):
        return collection_name.startswith(pattern.removesuffix("*"))

    return None
