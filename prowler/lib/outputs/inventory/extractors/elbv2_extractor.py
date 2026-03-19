from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract ELBv2 (ALB/NLB) load balancer nodes and their edges.

    Edges produced:
      - load_balancer → security-group  [network]
      - load_balancer → VPC             [network]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    for lb in client.loadbalancersv2.values():
        props = {
            "type": getattr(lb, "type", None),
            "scheme": getattr(lb, "scheme", None),
            "dns_name": getattr(lb, "dns", None),
            "vpc_id": getattr(lb, "vpc_id", None),
        }

        name = getattr(lb, "name", lb.arn.split("/")[-2] if "/" in lb.arn else lb.arn)

        nodes.append(
            ResourceNode(
                id=lb.arn,
                type="load_balancer",
                name=name,
                service="elbv2",
                region=lb.region,
                account_id=client.audited_account,
                properties={k: v for k, v in props.items() if v is not None},
            )
        )

        for sg_id in lb.security_groups or []:
            edges.append(
                ResourceEdge(
                    source_id=lb.arn,
                    target_id=sg_id,
                    edge_type="network",
                    label="sg",
                )
            )

        vpc_id = getattr(lb, "vpc_id", None)
        if vpc_id:
            edges.append(
                ResourceEdge(
                    source_id=lb.arn,
                    target_id=vpc_id,
                    edge_type="network",
                    label="in-vpc",
                )
            )

    return nodes, edges
