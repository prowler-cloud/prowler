from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract VPC and subnet nodes with their edges.

    Edges produced:
      - subnet → VPC  [depends_on]
      - peering connection between VPCs [network]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    # VPCs
    for vpc in client.vpcs.values():
        name = vpc.id if hasattr(vpc, "id") else vpc.arn
        for tag in vpc.tags or []:
            if isinstance(tag, dict) and tag.get("Key") == "Name":
                name = tag["Value"]
                break

        nodes.append(
            ResourceNode(
                id=vpc.arn,
                type="vpc",
                name=name,
                service="vpc",
                region=vpc.region,
                account_id=client.audited_account,
                properties={
                    "cidr_block": getattr(vpc, "cidr_block", None),
                    "is_default": getattr(vpc, "is_default", None),
                },
            )
        )

    # VPC Subnets
    for subnet in client.vpc_subnets.values():
        name = subnet.id if hasattr(subnet, "id") else subnet.arn
        for tag in getattr(subnet, "tags", None) or []:
            if isinstance(tag, dict) and tag.get("Key") == "Name":
                name = tag["Value"]
                break

        nodes.append(
            ResourceNode(
                id=subnet.arn,
                type="subnet",
                name=name,
                service="vpc",
                region=subnet.region,
                account_id=client.audited_account,
                properties={
                    "vpc_id": getattr(subnet, "vpc_id", None),
                    "cidr_block": getattr(subnet, "cidr_block", None),
                    "availability_zone": getattr(subnet, "availability_zone", None),
                    "public": getattr(subnet, "public", None),
                },
            )
        )

        vpc_id = getattr(subnet, "vpc_id", None)
        if vpc_id:
            # Find the VPC ARN for this vpc_id
            vpc_arn = next(
                (v.arn for v in client.vpcs.values() if v.id == vpc_id),
                vpc_id,
            )
            edges.append(
                ResourceEdge(
                    source_id=subnet.arn,
                    target_id=vpc_arn,
                    edge_type="depends_on",
                    label="subnet-of",
                )
            )

    # VPC Peering Connections
    for peering in getattr(client, "vpc_peering_connections", {}).values():
        edges.append(
            ResourceEdge(
                source_id=peering.arn,
                target_id=getattr(peering, "accepter_vpc_id", peering.arn),
                edge_type="network",
                label="vpc-peer",
            )
        )

    return nodes, edges
