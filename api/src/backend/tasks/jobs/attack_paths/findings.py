"""
Prowler findings ingestion into Neo4j graph.

This module handles:
- Adding resource labels to Cartography nodes for efficient lookups
- Loading Prowler findings into the graph
- Linking findings to resources
- Cleaning up stale findings
"""

from collections import defaultdict
from typing import Generator, TypedDict
from uuid import UUID

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
    render_cypher_template,
)

logger = get_task_logger(__name__)


# Type Definitions
# -----------------


class FindingRecord(TypedDict):
    """Raw finding record from Django query."""

    id: int
    uid: str
    inserted_at: str
    updated_at: str
    first_seen_at: str
    scan_id: str
    delta: str
    status: str
    status_extended: str
    severity: str
    check_id: str
    check_metadata__checktitle: str
    muted: bool
    muted_reason: str | None


class EnrichedFinding(TypedDict):
    """Finding data enriched with resource UID for Neo4j ingestion."""

    resource_uid: str
    id: str
    uid: str
    inserted_at: str
    updated_at: str
    first_seen_at: str
    scan_id: str
    delta: str
    status: str
    status_extended: str
    severity: str
    check_id: str
    check_title: str
    muted: bool
    muted_reason: str | None


# Fields to query from Finding model
FINDING_QUERY_FIELDS = (
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
)


# Public API
# ----------


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
    findings_data = stream_findings_with_resources(prowler_api_provider, scan_id)
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
    query = render_cypher_template(
        ADD_RESOURCE_LABEL_TEMPLATE,
        {
            "__ROOT_LABEL__": get_root_node_label(provider_type),
            "__RESOURCE_LABEL__": get_provider_resource_label(provider_type),
        },
    )

    logger.info(
        f"Adding {get_provider_resource_label(provider_type)} label to all resources for {provider_uid}"
    )

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
            logger.info(
                f"Labeled {total_labeled} nodes with {get_provider_resource_label(provider_type)}"
            )

    return total_labeled


def load_findings(
    neo4j_session: neo4j.Session,
    findings_batches: Generator[list[EnrichedFinding], None, None],
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    """Load Prowler findings into the graph, linking them to resources."""
    query = render_cypher_template(
        INSERT_FINDING_TEMPLATE,
        {
            "__ROOT_NODE_LABEL__": get_root_node_label(prowler_api_provider.provider),
            "__NODE_UID_FIELD__": get_node_uid_field(prowler_api_provider.provider),
            "__RESOURCE_LABEL__": get_provider_resource_label(
                prowler_api_provider.provider
            ),
        },
    )

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


# Findings Streaming (Generator-based)
# -------------------------------------


def stream_findings_with_resources(
    prowler_api_provider: Provider,
    scan_id: str,
) -> Generator[list[EnrichedFinding], None, None]:
    """
    Stream findings with their associated resources in batches.

    Uses keyset pagination for efficient traversal of large datasets.
    Memory efficient: yields one batch at a time, never holds all findings in memory.
    """
    logger.info(
        f"Starting findings stream for scan {scan_id} "
        f"(tenant {prowler_api_provider.tenant_id}) with batch size {BATCH_SIZE}"
    )

    tenant_id = prowler_api_provider.tenant_id
    for batch in _paginate_findings(tenant_id, scan_id):
        enriched = _enrich_batch_with_resources(batch, tenant_id)
        if enriched:
            yield enriched

    logger.info(f"Finished streaming findings for scan {scan_id}")


def _paginate_findings(
    tenant_id: str,
    scan_id: str,
) -> Generator[list[FindingRecord], None, None]:
    """
    Paginate through findings using keyset pagination.

    Each iteration fetches one batch within its own RLS transaction,
    preventing long-held database connections.
    """
    last_id = None
    iteration = 0

    while True:
        iteration += 1
        batch = _fetch_findings_batch(tenant_id, scan_id, last_id)

        logger.info(f"Iteration #{iteration}: fetched {len(batch)} findings")

        if not batch:
            break

        last_id = batch[-1]["id"]
        yield batch


def _fetch_findings_batch(
    tenant_id: str,
    scan_id: str,
    after_id: int | None,
) -> list[FindingRecord]:
    """
    Fetch a single batch of findings from the database.

    Uses read replica and RLS-scoped transaction.
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        # Use all_objects to avoid the ActiveProviderManager's implicit JOIN
        # through Scan -> Provider (to check is_deleted=False).
        # The provider is already validated as active in this context.
        qs = Finding.all_objects.filter(scan_id=scan_id).order_by("id")

        if after_id is not None:
            qs = qs.filter(id__gt=after_id)

        return list(qs.values(*FINDING_QUERY_FIELDS)[:BATCH_SIZE])


# Batch Enrichment
# -----------------


def _enrich_batch_with_resources(
    findings_batch: list[FindingRecord],
    tenant_id: str,
) -> list[EnrichedFinding]:
    """
    Enrich findings with their resource UIDs.

    One finding with N resources becomes N output records.
    Findings without resources are skipped.
    """
    finding_ids = [f["id"] for f in findings_batch]
    resource_map = _build_finding_resource_map(finding_ids, tenant_id)

    return [
        _to_enriched_finding(finding, resource_uid)
        for finding in findings_batch
        for resource_uid in resource_map.get(finding["id"], [])
    ]


def _build_finding_resource_map(
    finding_ids: list[UUID], tenant_id: str
) -> dict[UUID, list[str]]:
    """Build mapping from finding_id to list of resource UIDs."""
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        resource_mappings = ResourceFindingMapping.objects.filter(
            finding_id__in=finding_ids
        ).values_list("finding_id", "resource__uid")

        result = defaultdict(list)
        for finding_id, resource_uid in resource_mappings:
            result[finding_id].append(resource_uid)
        return result


def _to_enriched_finding(finding: FindingRecord, resource_uid: str) -> EnrichedFinding:
    """Convert a finding record to enriched format for Neo4j."""
    return {
        "resource_uid": str(resource_uid),
        "id": str(finding["id"]),
        "uid": finding["uid"],
        "inserted_at": finding["inserted_at"],
        "updated_at": finding["updated_at"],
        "first_seen_at": finding["first_seen_at"],
        "scan_id": str(finding["scan_id"]),
        "delta": finding["delta"],
        "status": finding["status"],
        "status_extended": finding["status_extended"],
        "severity": finding["severity"],
        "check_id": str(finding["check_id"]),
        "check_title": finding["check_metadata__checktitle"],
        "muted": finding["muted"],
        "muted_reason": finding["muted_reason"],
    }
