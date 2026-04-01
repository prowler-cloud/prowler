from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract Lambda function nodes and their edges from an awslambda_client.

    Edges produced:
      - lambda → VPC         [network]
      - lambda → subnet      [network]
      - lambda → sg          [network]
      - lambda → event-source[triggers]  (from EventSourceMapping)
      - lambda → layer ARN   [depends_on]
      - lambda → DLQ target  [data_flow]
      - lambda → KMS key     [encrypts]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    for fn in client.functions.values():
        props = {
            "runtime": fn.runtime,
            "vpc_id": fn.vpc_id,
        }
        if fn.environment:
            props["has_env_vars"] = True
        if fn.kms_key_arn:
            props["kms_key_arn"] = fn.kms_key_arn

        nodes.append(
            ResourceNode(
                id=fn.arn,
                type="lambda_function",
                name=fn.name,
                service="lambda",
                region=fn.region,
                account_id=client.audited_account,
                properties=props,
            )
        )

        # Network edges → VPC, subnets, security groups
        if fn.vpc_id:
            edges.append(
                ResourceEdge(
                    source_id=fn.arn,
                    target_id=fn.vpc_id,
                    edge_type="network",
                    label="in-vpc",
                )
            )
        for sg_id in fn.security_groups or []:
            edges.append(
                ResourceEdge(
                    source_id=fn.arn,
                    target_id=sg_id,
                    edge_type="network",
                    label="sg",
                )
            )
        for subnet_id in fn.subnet_ids or set():
            edges.append(
                ResourceEdge(
                    source_id=fn.arn,
                    target_id=subnet_id,
                    edge_type="network",
                    label="subnet",
                )
            )

        # Trigger edges from event source mappings
        for esm in getattr(fn, "event_source_mappings", []):
            edges.append(
                ResourceEdge(
                    source_id=esm.event_source_arn,
                    target_id=fn.arn,
                    edge_type="triggers",
                    label=f"esm:{esm.state}",
                )
            )

        # Layer dependency edges
        for layer in getattr(fn, "layers", []):
            edges.append(
                ResourceEdge(
                    source_id=fn.arn,
                    target_id=layer.arn,
                    edge_type="depends_on",
                    label="layer",
                )
            )

        # Dead-letter queue data-flow edge
        dlq = getattr(fn, "dead_letter_config", None)
        if dlq and dlq.target_arn:
            edges.append(
                ResourceEdge(
                    source_id=fn.arn,
                    target_id=dlq.target_arn,
                    edge_type="data_flow",
                    label="dlq",
                )
            )

        # KMS encryption edge
        if fn.kms_key_arn:
            edges.append(
                ResourceEdge(
                    source_id=fn.kms_key_arn,
                    target_id=fn.arn,
                    edge_type="encrypts",
                    label="kms",
                )
            )

    return nodes, edges
