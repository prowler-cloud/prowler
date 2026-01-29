"""
Prowler findings ingestion into Neo4j graph.

This module handles:
- Adding resource labels to Cartography nodes for efficient lookups
- Loading Prowler findings into the graph
- Linking findings to resources
- Cleaning up stale findings
"""

from collections import defaultdict
from typing import Generator

import neo4j

from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Provider, ResourceFindingMapping
from prowler.config import config as ProwlerConfig
from tasks.jobs.attack_paths.config import (
    BATCH_SIZE,
    get_node_uid_field,
    get_provider_resource_label,
    get_root_node_label,
)
from tasks.jobs.attack_paths.indexes import IndexType, create_indexes
from tasks.jobs.attack_paths.queries import (
    ADD_RESOURCE_LABEL_TEMPLATE,
    CLEANUP_FINDINGS_TEMPLATE,
    INSERT_FINDING_TEMPLATE,
)

logger = get_task_logger(__name__)


def create_findings_indexes(neo4j_session: neo4j.Session) -> None:
    """Create indexes for Prowler findings and resource lookups."""
    create_indexes(neo4j_session, IndexType.FINDINGS)


def analysis(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    scan_id: str,
    config: CartographyConfig,
) -> None:
    """
    Main entry point for Prowler findings analysis.

    Adds resource labels, loads findings, and cleans up stale data.
    """
    add_resource_label(
        neo4j_session, prowler_api_provider.provider, str(prowler_api_provider.uid)
    )
    findings_data = get_provider_last_scan_findings(prowler_api_provider, scan_id)
    load_findings(neo4j_session, findings_data, prowler_api_provider, config)
    cleanup_findings(neo4j_session, prowler_api_provider, config)


def add_resource_label(
    neo4j_session: neo4j.Session, provider_type: str, provider_uid: str
) -> int:
    """
    Add a common resource label to all nodes connected to the provider account.

    This enables index usage for resource lookups in the findings query,
    since Cartography nodes don't have a common parent label.

    Returns the total number of nodes labeled.
    """
    root_label = get_root_node_label(provider_type)
    resource_label = get_provider_resource_label(provider_type)

    replacements = {
        "__ROOT_LABEL__": root_label,
        "__RESOURCE_LABEL__": resource_label,
    }
    query = ADD_RESOURCE_LABEL_TEMPLATE
    for replace_key, replace_value in replacements.items():
        query = query.replace(replace_key, replace_value)

    logger.info(f"Adding {resource_label} label to all resources for {provider_uid}")

    total_labeled = 0
    labeled_count = 1

    while labeled_count > 0:
        result = neo4j_session.run(
            query,
            {"provider_uid": provider_uid, "batch_size": BATCH_SIZE},
        )
        labeled_count = result.single().get("labeled_count", 0)
        total_labeled += labeled_count

        if labeled_count > 0:
            logger.info(f"Labeled {total_labeled} nodes with {resource_label}")

    return total_labeled


def get_provider_last_scan_findings(
    prowler_api_provider: Provider,
    scan_id: str,
) -> Generator[list[dict[str, str]], None, None]:
    """
    Generator that yields batches of finding-resource pairs.

    Two-step query approach per batch:
    1. Paginate findings for scan (single table, indexed by scan_id)
    2. Batch-fetch resource UIDs via mapping table (single join)
    3. Merge and yield flat structure for Neo4j

    Memory efficient: never holds more than `BATCH_SIZE` findings in memory.
    """

    logger.info(
        f"Starting findings fetch for scan {scan_id} (tenant {prowler_api_provider.tenant_id}) with batch size {BATCH_SIZE}"
    )

    iteration = 0
    last_id = None

    while True:
        iteration += 1

        with rls_transaction(prowler_api_provider.tenant_id, using=READ_REPLICA_ALIAS):
            # Use all_objects to avoid the ActiveProviderManager's implicit JOIN
            # through Scan -> Provider (to check is_deleted=False).
            # The provider is already validated as active in this context.
            qs = Finding.all_objects.filter(scan_id=scan_id).order_by("id")
            if last_id is not None:
                qs = qs.filter(id__gt=last_id)

            findings_batch = list(
                qs.values(
                    "id",
                    "uid",
                    "inserted_at",
                    "updated_at",
                    "first_seen_at",
                    "scan_id",
                    "delta",
                    "status",
                    "status_extended",
                    "severity",
                    "check_id",
                    "check_metadata__checktitle",
                    "muted",
                    "muted_reason",
                )[:BATCH_SIZE]
            )

            logger.info(
                f"Iteration #{iteration} fetched {len(findings_batch)} findings"
            )

            if not findings_batch:
                logger.info(
                    f"No findings returned for iteration #{iteration}; stopping pagination"
                )
                break

            last_id = findings_batch[-1]["id"]
            enriched_batch = _enrich_and_flatten_batch(findings_batch)

        # Yield outside the transaction
        if enriched_batch:
            yield enriched_batch

    logger.info(f"Finished fetching findings for scan {scan_id}")


def _enrich_and_flatten_batch(
    findings_batch: list[dict],
) -> list[dict[str, str]]:
    """
    Fetch resource UIDs for a batch of findings and return flat structure.

    One finding with 3 resources becomes 3 dicts (same output format as before).
    Must be called within an RLS transaction context.
    """
    finding_ids = [f["id"] for f in findings_batch]

    # Single join: mapping -> resource
    resource_mappings = ResourceFindingMapping.objects.filter(
        finding_id__in=finding_ids
    ).values_list("finding_id", "resource__uid")

    # Build finding_id -> [resource_uids] mapping
    finding_resources = defaultdict(list)
    for finding_id, resource_uid in resource_mappings:
        finding_resources[finding_id].append(resource_uid)

    # Flatten: one dict per (finding, resource) pair
    results = []
    for f in findings_batch:
        resource_uids = finding_resources.get(f["id"], [])

        if not resource_uids:
            continue

        for resource_uid in resource_uids:
            results.append(
                {
                    "resource_uid": str(resource_uid),
                    "id": str(f["id"]),
                    "uid": f["uid"],
                    "inserted_at": f["inserted_at"],
                    "updated_at": f["updated_at"],
                    "first_seen_at": f["first_seen_at"],
                    "scan_id": str(f["scan_id"]),
                    "delta": f["delta"],
                    "status": f["status"],
                    "status_extended": f["status_extended"],
                    "severity": f["severity"],
                    "check_id": str(f["check_id"]),
                    "check_title": f["check_metadata__checktitle"],
                    "muted": f["muted"],
                    "muted_reason": f["muted_reason"],
                }
            )

    return results


def load_findings(
    neo4j_session: neo4j.Session,
    findings_batches: Generator[list[dict[str, str]], None, None],
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    """Load Prowler findings into the graph, linking them to resources."""
    replacements = {
        "__ROOT_NODE_LABEL__": get_root_node_label(prowler_api_provider.provider),
        "__NODE_UID_FIELD__": get_node_uid_field(prowler_api_provider.provider),
        "__RESOURCE_LABEL__": get_provider_resource_label(
            prowler_api_provider.provider
        ),
    }
    query = INSERT_FINDING_TEMPLATE
    for replace_key, replace_value in replacements.items():
        query = query.replace(replace_key, replace_value)

    parameters = {
        "provider_uid": str(prowler_api_provider.uid),
        "last_updated": config.update_tag,
        "prowler_version": ProwlerConfig.prowler_version,
    }

    batch_num = 0
    total_records = 0
    for batch in findings_batches:
        batch_num += 1
        batch_size = len(batch)
        total_records += batch_size

        parameters["findings_data"] = batch

        logger.info(f"Loading findings batch {batch_num} ({batch_size} records)")
        neo4j_session.run(query, parameters)

    logger.info(f"Finished loading {total_records} records in {batch_num} batches")


def cleanup_findings(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    """Remove stale findings (classic Cartography behaviour)."""
    parameters = {
        "provider_uid": str(prowler_api_provider.uid),
        "last_updated": config.update_tag,
        "batch_size": BATCH_SIZE,
    }

    batch = 1
    deleted_count = 1
    while deleted_count > 0:
        logger.info(f"Cleaning findings batch {batch}")

        result = neo4j_session.run(CLEANUP_FINDINGS_TEMPLATE, parameters)

        deleted_count = result.single().get("deleted_findings_count", 0)
        batch += 1
