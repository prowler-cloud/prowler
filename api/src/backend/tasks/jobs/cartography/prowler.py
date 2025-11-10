import neo4j

from cartography.client.core.tx import run_write_query
from cartography.config import Config as CartographyConfig
from celery.utils.log import get_task_logger
from django.db.models import Subquery

from api.db_utils import rls_transaction
from api.models import Provider, ResourceFindingMapping, Scan
from config.env import env
from prowler.config import config as ProwlerConfig

logger = get_task_logger(__name__)

BATCH_SIZE = env.int("NEO4J_INSERT_BATCH_SIZE", 500)

ROOT_NODE_LABELS = {
    "aws": "AWSAccount",
}

NODE_UID_FIELDS = {
    "aws": "arn",
}

INDEX_STATEMENTS = [
    "CREATE INDEX prowler_finding_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.id);",
    "CREATE INDEX prowler_finding_account_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.account_id);",
    "CREATE INDEX prowler_finding_lastupdated IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.lastupdated);",
    "CREATE INDEX prowler_finding_check_id IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.check_id);",
    "CREATE INDEX prowler_finding_severity IF NOT EXISTS FOR (n:ProwlerFinding) ON (n.severity);",
]

INSERT_STATEMENT_TEMPLATE = """
    UNWIND $findings_data AS finding_data

    MATCH (account:__ROOT_NODE_LABEL__ {id: $account_id})
    MATCH (account)-->(resource)
        WHERE resource.__NODE_UID_FIELD__ = finding_data.resource_uid
            OR resource.id = finding_data.resource_uid

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
            finding.muted = finding_data.muted,
            finding.muted_reason = finding_data.muted_reason,
            finding.account_id = $account_id,
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
            rel.account_id = $account_id,
            rel.firstseen = timestamp(),
            rel.lastupdated = $last_updated,
            rel._module_name = 'cartography:prowler',
            rel._module_version = $prowler_version
        ON MATCH SET
            rel.lastupdated = $last_updated
"""

CLEANUP_STATEMENT = """
    MATCH (finding:ProwlerFinding {account_id: $account_id})
        WHERE finding.lastupdated < $last_updated

    WITH finding LIMIT $batch_size

    DETACH DELETE finding

    RETURN COUNT(finding) AS deleted_findings_count
"""


def create_indexes(neo4j_session: neo4j.Session) -> None:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.intel.create_indexes.run`.
    """

    logger.info("Creating indexes for Prowler node types.")
    for statement in INDEX_STATEMENTS:
        logger.debug("Executing statement: %s", statement)
        run_write_query(neo4j_session, statement)


def analysis(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    findings_data = get_provider_last_scan_findings(prowler_api_provider)
    load_findings(neo4j_session, findings_data, prowler_api_provider, config)
    cleanup_findings(neo4j_session, prowler_api_provider, config)


def get_provider_last_scan_findings(
    prowler_api_provider: Provider,
) -> list[dict[str, str]]:
    with rls_transaction(prowler_api_provider.tenant_id):
        latest_scan_id_subquery = (
            Scan.objects.filter(
                provider_id=prowler_api_provider.id
            )
            .order_by("-updated_at")
            .values("id")[:1]
        )

        resource_finding_qs = ResourceFindingMapping.objects.filter(
            finding__scan_id=Subquery(latest_scan_id_subquery),
        ).values(
            "resource__uid",
            "finding__id",
            "finding__uid",
            "finding__inserted_at",
            "finding__updated_at",
            "finding__first_seen_at",
            "finding__scan_id",
            "finding__delta",
            "finding__status",
            "finding__status_extended",
            "finding__severity",
            "finding__check_id",
            "finding__muted",
            "finding__muted_reason",
        )

        findings = []
        for resource_finding in resource_finding_qs:
            findings.append(
                {
                    "resource_uid": str(resource_finding["resource__uid"]),
                    "id": str(resource_finding["finding__id"]),
                    "uid": resource_finding["finding__uid"],
                    "inserted_at": resource_finding["finding__inserted_at"],
                    "updated_at": resource_finding["finding__updated_at"],
                    "first_seen_at": resource_finding["finding__first_seen_at"],
                    "scan_id": str(resource_finding["finding__scan_id"]),
                    "delta": resource_finding["finding__delta"],
                    "status": resource_finding["finding__status"],
                    "status_extended": resource_finding["finding__status_extended"],
                    "severity": resource_finding["finding__severity"],
                    "check_id": str(resource_finding["finding__check_id"]),
                    "muted": resource_finding["finding__muted"],
                    "muted_reason": resource_finding["finding__muted_reason"],
                }
            )

        return findings


def load_findings(
    neo4j_session: neo4j.Session,
    findings_data: list[dict[str, str]],
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    replacements = {
        "__ROOT_NODE_LABEL__": ROOT_NODE_LABELS[prowler_api_provider.provider],
        "__NODE_UID_FIELD__": NODE_UID_FIELDS[prowler_api_provider.provider],
    }
    query = INSERT_STATEMENT_TEMPLATE
    for replace_key, replace_value in replacements.items():
        query = query.replace(replace_key, replace_value)

    parameters = {
        "account_id": str(prowler_api_provider.uid),
        "last_updated": config.update_tag,
        "prowler_version": ProwlerConfig.prowler_version,
    }

    total_length = len(findings_data)
    for i in range(0, total_length, BATCH_SIZE):
        parameters["findings_data"] = findings_data[i : i + BATCH_SIZE]

        logger.info(
            f"Loading findings batch {i // BATCH_SIZE + 1} / {(total_length + BATCH_SIZE - 1) // BATCH_SIZE}"
        )

        neo4j_session.run(
            query=query,
            parameters=parameters,
        )


def cleanup_findings(
    neo4j_session: neo4j.Session,
    prowler_api_provider: Provider,
    config: CartographyConfig,
) -> None:
    parameters = {
        "account_id": str(prowler_api_provider.uid),
        "last_updated": config.update_tag,
        "batch_size": BATCH_SIZE,
    }

    batch = 1
    deleted_count = 1
    while deleted_count > 0:
        logger.info(f"Cleaning findings batch {batch}")

        result = neo4j_session.run(
            query=CLEANUP_STATEMENT,
            parameters=parameters,
        )

        deleted_count = result.single().get("deleted_findings_count", 0)
        batch += 1
