from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract EC2 instance and security-group nodes with their edges.

    Edges produced:
      - instance → security-group  [network]
      - instance → subnet          [network]
      - security-group → VPC       [network]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    # EC2 Instances
    for instance in client.instances:
        name = instance.id
        for tag in instance.tags or []:
            if tag.get("Key") == "Name":
                name = tag["Value"]
                break

        props = {
            "instance_type": getattr(instance, "type", None),
            "state": getattr(instance, "state", None),
            "vpc_id": getattr(instance, "vpc_id", None),
            "subnet_id": getattr(instance, "subnet_id", None),
            "public_ip": getattr(instance, "public_ip_address", None),
            "private_ip": getattr(instance, "private_ip_address", None),
        }

        nodes.append(
            ResourceNode(
                id=instance.arn,
                type="ec2_instance",
                name=name,
                service="ec2",
                region=instance.region,
                account_id=client.audited_account,
                properties={k: v for k, v in props.items() if v is not None},
            )
        )

        for sg_id in instance.security_groups or []:
            edges.append(
                ResourceEdge(
                    source_id=instance.arn,
                    target_id=sg_id,
                    edge_type="network",
                    label="sg",
                )
            )

        if instance.subnet_id:
            edges.append(
                ResourceEdge(
                    source_id=instance.arn,
                    target_id=instance.subnet_id,
                    edge_type="network",
                    label="subnet",
                )
            )

    # Security Groups
    for sg in client.security_groups.values():
        name = sg.name if hasattr(sg, "name") else sg.id if hasattr(sg, "id") else sg.arn
        nodes.append(
            ResourceNode(
                id=sg.arn,
                type="security_group",
                name=name,
                service="ec2",
                region=sg.region,
                account_id=client.audited_account,
                properties={"vpc_id": sg.vpc_id},
            )
        )

        if sg.vpc_id:
            edges.append(
                ResourceEdge(
                    source_id=sg.arn,
                    target_id=sg.vpc_id,
                    edge_type="network",
                    label="in-vpc",
                )
            )

    return nodes, edges
