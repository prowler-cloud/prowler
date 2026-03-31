import neo4j

from cartography.client.core.tx import run_write_query
from celery.utils.log import get_task_logger

from tasks.jobs.attack_paths.config import (
    INTERNET_NODE_LABEL,
    PROWLER_FINDING_LABEL,
    PROVIDER_ELEMENT_ID_PROPERTY,
    PROVIDER_RESOURCE_LABEL,
)

logger = get_task_logger(__name__)


# Indexes for Prowler findings and resource lookups
FINDINGS_INDEX_STATEMENTS = [
    # Resource indexes for Prowler Finding lookups
    "CREATE INDEX aws_resource_arn IF NOT EXISTS FOR (n:_AWSResource) ON (n.arn);",
    "CREATE INDEX aws_resource_id IF NOT EXISTS FOR (n:_AWSResource) ON (n.id);",
    # Prowler Finding indexes
    f"CREATE INDEX prowler_finding_id IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.id);",
    f"CREATE INDEX prowler_finding_lastupdated IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.lastupdated);",
    f"CREATE INDEX prowler_finding_status IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.status);",
    # Internet node index for MERGE lookups
    f"CREATE INDEX internet_id IF NOT EXISTS FOR (n:{INTERNET_NODE_LABEL}) ON (n.id);",
]

# Indexes for provider resource sync operations
SYNC_INDEX_STATEMENTS = [
    f"CREATE INDEX provider_resource_element_id IF NOT EXISTS FOR (n:{PROVIDER_RESOURCE_LABEL}) ON (n.{PROVIDER_ELEMENT_ID_PROPERTY});",
]


def create_findings_indexes(neo4j_session: neo4j.Session) -> None:
    """Create indexes for Prowler findings and resource lookups."""
    logger.info("Creating indexes for Prowler Findings node types")
    for statement in FINDINGS_INDEX_STATEMENTS:
        run_write_query(neo4j_session, statement)


def create_sync_indexes(neo4j_session: neo4j.Session) -> None:
    """Create indexes for provider resource sync operations."""
    logger.info("Ensuring ProviderResource indexes exist")
    for statement in SYNC_INDEX_STATEMENTS:
        neo4j_session.run(statement)
