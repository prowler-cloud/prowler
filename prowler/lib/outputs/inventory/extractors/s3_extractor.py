from typing import List, Tuple

from prowler.lib.outputs.inventory.models import ResourceEdge, ResourceNode


def extract(client) -> Tuple[List[ResourceNode], List[ResourceEdge]]:
    """
    Extract S3 bucket nodes and their edges.

    Edges produced:
      - bucket → replication-target bucket  [replicates_to]
      - bucket → KMS key                    [encrypts]
      - bucket → logging bucket             [logs_to]
    """
    nodes: List[ResourceNode] = []
    edges: List[ResourceEdge] = []

    for bucket in client.buckets.values():
        encryption = getattr(bucket, "encryption", None)
        versioning = getattr(bucket, "versioning_enabled", None)
        logging = getattr(bucket, "logging", None)
        public = getattr(bucket, "public_access_block", None)

        props = {}
        if versioning is not None:
            props["versioning"] = versioning
        if encryption:
            enc_type = getattr(encryption, "type", str(encryption))
            props["encryption"] = enc_type

        nodes.append(
            ResourceNode(
                id=bucket.arn,
                type="s3_bucket",
                name=bucket.name,
                service="s3",
                region=bucket.region,
                account_id=client.audited_account,
                properties=props,
            )
        )

        # Replication edges
        for rule in getattr(bucket, "replication_rules", None) or []:
            dest_bucket = getattr(rule, "destination_bucket", None)
            if dest_bucket:
                dest_arn = (
                    dest_bucket
                    if dest_bucket.startswith("arn:")
                    else f"arn:aws:s3:::{dest_bucket}"
                )
                edges.append(
                    ResourceEdge(
                        source_id=bucket.arn,
                        target_id=dest_arn,
                        edge_type="replicates_to",
                        label="s3-replication",
                    )
                )

        # Logging edges
        if logging:
            target_bucket = getattr(logging, "target_bucket", None)
            if target_bucket:
                target_arn = (
                    target_bucket
                    if target_bucket.startswith("arn:")
                    else f"arn:aws:s3:::{target_bucket}"
                )
                edges.append(
                    ResourceEdge(
                        source_id=bucket.arn,
                        target_id=target_arn,
                        edge_type="logs_to",
                        label="access-logs",
                    )
                )

        # KMS encryption edges
        if encryption:
            kms_arn = getattr(encryption, "kms_master_key_id", None)
            if kms_arn:
                edges.append(
                    ResourceEdge(
                        source_id=kms_arn,
                        target_id=bucket.arn,
                        edge_type="encrypts",
                        label="kms",
                    )
                )

    return nodes, edges
