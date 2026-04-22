from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract RDS DB instance nodes and their edges.

    Edges produced:
      - db_instance → security-group  [network]
      - db_instance → VPC             [network]
      - db_instance → cluster         [depends_on]
      - db_instance → KMS key         [encrypts]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    for db in client.db_instances.values():
        props = {
            "engine": getattr(db, "engine", None),
            "engine_version": getattr(db, "engine_version", None),
            "instance_class": getattr(db, "db_instance_class", None),
            "vpc_id": getattr(db, "vpc_id", None),
            "multi_az": getattr(db, "multi_az", None),
            "publicly_accessible": getattr(db, "publicly_accessible", None),
            "storage_encrypted": getattr(db, "storage_encrypted", None),
        }

        nodes.append(
            ResourceNode(
                id=db.arn,
                type="rds_instance",
                name=db.id,
                service="rds",
                region=db.region,
                account_id=client.audited_account,
                properties={k: v for k, v in props.items() if v is not None},
            )
        )

        for sg in getattr(db, "security_groups", []):
            sg_id = sg if isinstance(sg, str) else getattr(sg, "id", str(sg))
            edges.append(
                ResourceEdge(
                    source_id=db.arn,
                    target_id=sg_id,
                    edge_type="network",
                    label="sg",
                )
            )

        vpc_id = getattr(db, "vpc_id", None)
        if vpc_id:
            edges.append(
                ResourceEdge(
                    source_id=db.arn,
                    target_id=vpc_id,
                    edge_type="network",
                    label="in-vpc",
                )
            )

        cluster_arn = getattr(db, "cluster_arn", None)
        if cluster_arn:
            edges.append(
                ResourceEdge(
                    source_id=db.arn,
                    target_id=cluster_arn,
                    edge_type="depends_on",
                    label="cluster-member",
                )
            )

        kms_key_id = getattr(db, "kms_key_id", None)
        if kms_key_id:
            edges.append(
                ResourceEdge(
                    source_id=kms_key_id,
                    target_id=db.arn,
                    edge_type="encrypts",
                    label="kms",
                )
            )

    return nodes, edges
