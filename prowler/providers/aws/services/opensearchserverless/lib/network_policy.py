from typing import Optional

from pydantic.v1 import BaseModel


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


class NetworkPolicyRule(BaseModel):
    """A single rule from an OpenSearch Serverless network policy.

    Each rule is flattened from its policy block, so it carries the block's
    public access setting.

    Attributes:
        policy_name: Name of the network policy the rule belongs to.
        resource_type: Endpoint the rule applies to: "collection" (API) or
            "dashboard" (OpenSearch Dashboards).
        patterns: Resource patterns the rule applies to, with the
            "collection/" prefix. They may contain wildcards, so they are
            not collection names.
        allow_from_public: True if the rule's block allows access from the
            public internet. Inherited from the block, not set per rule.
    """

    policy_name: str
    resource_type: str
    patterns: list[str]
    allow_from_public: bool


def parse_network_policy(
    policy_name: str, policy_document
) -> Optional[list[NetworkPolicyRule]]:
    """Flatten an OpenSearch Serverless network policy into rules.

    AWS nests rules inside blocks, and each block sets public access for
    all of its rules. This function returns one rule per entry with that
    setting attached, so callers do not need to know the AWS format.

    Args:
        policy_name: Name of the network policy.
        policy_document: The "policy" field returned by get_security_policy.
            Expected to be a list of blocks, each with "Rules" and
            "AllowFromPublic".

    Returns:
        A list of NetworkPolicyRule, one per rule in the policy.
        An empty list if the policy has no rules, so it grants no access.
        None if the document has an unexpected shape. Unreadable parts
        could grant public access, so the policy must not be ignored:
        callers should treat their inventory as incomplete.
    """
    # 1. Si el documento no es una lista → None
    if not isinstance(policy_document, list):
        return None

    # 2. Preparar una lista vacía de resultados
    resultados = []

    # 3. Recorrer cada bloque:
    #    a. Si el bloque no es un diccionario → None
    for elemento in policy_document:
        if not isinstance(elemento, dict):
            return None

        #    b. Si AllowFromPublic no es un booleano (falta, o es texto) → None
        if not isinstance(elemento.get("AllowFromPublic"), bool):
            return None
        allow_from_public = elemento.get("AllowFromPublic")

        #    c. Si Rules no es una lista → None
        if not isinstance(elemento.get("Rules"), list):
            return None

        #    d. Recorrer cada regla del bloque:
        for subelemento in elemento.get("Rules"):
            #       - Si la regla no es un diccionario → None
            if not isinstance(subelemento, dict):
                return None

            #       - Si ResourceType no es "collection" ni "dashboard" (o falta) → None
            if subelemento.get("ResourceType") not in {"collection", "dashboard"}:
                return None

            #       - Si Resource no es una lista → None
            if not isinstance(subelemento.get("Resource"), list):
                return None

            #       - Añadir un NetworkPolicyRule a los resultados
            resultados.append(
                NetworkPolicyRule(
                    policy_name=policy_name,
                    resource_type=subelemento.get("ResourceType"),
                    patterns=subelemento.get("Resource"),
                    allow_from_public=allow_from_public,
                )
            )
    # 4. Devolver los resultados
    return resultados
