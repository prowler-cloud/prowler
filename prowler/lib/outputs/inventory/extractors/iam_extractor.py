import json
from typing import Any, Dict, List, Tuple

from prowler.lib.logger import logger
from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def _parse_trust_principals(assume_role_policy: Any) -> List[str]:
    """
    Return a flat list of principal strings from an IAM assume-role policy document.
    The policy may be a dict already or a JSON string.
    """
    if not assume_role_policy:
        return []

    if isinstance(assume_role_policy, str):
        try:
            assume_role_policy = json.loads(assume_role_policy)
        except (json.JSONDecodeError, ValueError):
            return []

    principals = []
    for statement in assume_role_policy.get("Statement", []):
        principal = statement.get("Principal", {})
        if isinstance(principal, str):
            principals.append(principal)
        elif isinstance(principal, dict):
            for v in principal.values():
                if isinstance(v, list):
                    principals.extend(v)
                else:
                    principals.append(v)
        elif isinstance(principal, list):
            principals.extend(principal)

    return principals


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract IAM role nodes and their trust-relationship edges.

    Edges produced:
      - trusted-principal → role  [iam]  (who can assume this role)
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    for role in client.roles:
        props: Dict[str, Any] = {
            "path": getattr(role, "path", None),
            "create_date": str(getattr(role, "create_date", "") or ""),
        }

        nodes.append(
            ResourceNode(
                id=role.arn,
                type="iam_role",
                name=role.name,
                service="iam",
                region="global",
                account_id=client.audited_account,
                properties={k: v for k, v in props.items() if v},
            )
        )

        # Trust-relationship edges: principal → role (principal CAN assume role)
        try:
            for principal in _parse_trust_principals(role.assume_role_policy):
                if principal and principal != "*":
                    edges.append(
                        ResourceEdge(
                            source_id=principal,
                            target_id=role.arn,
                            edge_type="iam",
                            label="can-assume",
                        )
                    )
        except Exception as e:
            logger.debug(f"inventory iam_extractor: could not parse trust policy for {role.arn}: {e}")

    return nodes, edges
