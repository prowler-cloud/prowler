from collections import defaultdict
from typing import Generator

import neo4j
from cartography.client.core.tx import run_write_query
from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger
from config.env import env
from tasks.jobs.attack_paths.providers import get_node_uid_field, get_root_node_label

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Provider, ResourceFindingMapping
from prowler.config import config as ProwlerConfig

logger = get_task_logger(__name__)

BATCH_SIZE = env.int("ATTACK_PATHS_FINDINGS_BATCH_SIZE", 1000)

INDEX_STATEMENTS = [
    "CREATE INDEX prowler_finding_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.id);",
    "CREATE INDEX prowler_finding_provider_uid IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.provider_uid);",
    "CREATE INDEX prowler_finding_lastupdated IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.lastupdated);",
    "CREATE INDEX prowler_finding_check_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.status);",
]

INSERT_STATEMENT_TEMPLATE = """
    MATCH (account:__ROOT_NODE_LABEL__ {id: $provider_uid})
    UNWIND $findings_data AS finding_data

    OPTIONAL MATCH (account)-->(resource_by_uid)
        WHERE resource_by_uid.__NODE_UID_FIELD__ = finding_data.resource_uid
    WITH account, finding_data, resource_by_uid

    OPTIONAL MATCH (account)-->(resource_by_id)
        WHERE resource_by_uid IS NULL
            AND resource_by_id.id = finding_data.resource_uid
    WITH account, finding_data, COALESCE(resource_by_uid, resource_by_id) AS resource
        WHERE resource IS NOT NULL

    MERGE (finding:ProwlerFinding {id: finding_data.id})
        ON CREATE SET
            finding.id = finding_data.id,
            finding.uid = finding_data.uid,
            finding.inserted_at = finding_data.inserted_at,
            finding.updated_at = finding_data.updated_at,
            finding.first_seen_at = finding_data.first_seen_at,
            finding.scan_id = finding_data.scan_id,
            finding.delta = finding_data.delta,
            finding.status = finding_data.status,
            finding.status_extended = finding_data.status_extended,
            finding.severity = finding_data.severity,
            finding.check_id = finding_data.check_id,
            finding.check_title = finding_data.check_title,
            finding.muted = finding_data.muted,
            finding.muted_reason = finding_data.muted_reason,
            finding.provider_uid = $provider_uid,
            finding.firstseen = timestamp(),
            finding.lastupdated = $last_updated,
            finding._module_name = 'cartography:prowler',
            finding._module_version = $prowler_version
        ON MATCH SET
            finding.status = finding_data.status,
            finding.status_extended = finding_data.status_extended,
            finding.lastupdated = $last_updated

    MERGE (resource)-[rel:HAS_FINDING]->(finding)
        ON CREATE SET
            rel.provider_uid = $provider_uid,
            rel.firstseen = timestamp(),
            rel.lastupdated = $last_updated,
            rel._module_name = 'cartography:prowler',
            rel._module_version = $prowler_version
        ON MATCH SET
            rel.lastupdated = $last_updated
"""

CLEANUP_STATEMENT = """
    MATCH (finding:ProwlerFinding {provider_uid: $provider_uid})
        WHERE finding.lastupdated < $last_updated

    WITH finding LIMIT $batch_size

    DETACH DELETE finding

    RETURN COUNT(finding) AS deleted_findings_count
"""


def create_indexes(neo4j_session: neo4j.Session) -> None:
    """
    Code based on Cartography version 0.122.0, specifically on `cartography.intel.create_indexes.run`.
    """

    logger.info("Creating indexes for Prowler Findings node types")
    for statement in INDEX_STATEMENTS:
        run_write_query(neo4j_session, statement)


def analysis(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    scan_id: str,
    config: CartographyConfig,
) -> None:
    findings_data = get_provider_last_scan_findings(prowler_api_provider, scan_id)
    load_findings(neo4j_session, findings_data, prowler_api_provider, config)
    cleanup_findings(neo4j_session, prowler_api_provider, config)


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

    Memory efficient: never holds more than BATCH_SIZE findings in memory.
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
    replacements = {
        "__ROOT_NODE_LABEL__": get_root_node_label(prowler_api_provider.provider),
        "__NODE_UID_FIELD__": get_node_uid_field(prowler_api_provider.provider),
    }
    query = INSERT_STATEMENT_TEMPLATE
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
    parameters = {
        "provider_uid": str(prowler_api_provider.uid),
        "last_updated": config.update_tag,
        "batch_size": BATCH_SIZE,
    }

    batch = 1
    deleted_count = 1
    while deleted_count > 0:
        logger.info(f"Cleaning findings batch {batch}")

        result = neo4j_session.run(CLEANUP_STATEMENT, parameters)

        deleted_count = result.single().get("deleted_findings_count", 0)
        batch += 1
