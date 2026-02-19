from enum import Enum

import neo4j

from cartography.client.core.tx import run_write_query
from celery.utils.log import get_task_logger

from tasks.jobs.attack_paths.config import (
    DEPRECATED_PROVIDER_RESOURCE_LABEL,
    INTERNET_NODE_LABEL,
    PROWLER_FINDING_LABEL,
    PROVIDER_RESOURCE_LABEL,
)

logger = get_task_logger(__name__)


class IndexType(Enum):
    """Types of indexes that can be created."""

    FINDINGS = "findings"
    SYNC = "sync"


# Indexes for Prowler findings and resource lookups
FINDINGS_INDEX_STATEMENTS = [
    # Resource indexes for Prowler Finding lookups
    "CREATE INDEX aws_resource_arn IF NOT EXISTS FOR (n:_AWSResource) ON (n.arn);",
    "CREATE INDEX aws_resource_id IF NOT EXISTS FOR (n:_AWSResource) ON (n.id);",
    "CREATE INDEX deprecated_aws_resource_arn IF NOT EXISTS FOR (n:AWSResource) ON (n.arn);",
    "CREATE INDEX deprecated_aws_resource_id IF NOT EXISTS FOR (n:AWSResource) ON (n.id);",
    # Prowler Finding indexes
    f"CREATE INDEX prowler_finding_id IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.id);",
    f"CREATE INDEX prowler_finding_provider_uid IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.provider_uid);",
    f"CREATE INDEX prowler_finding_lastupdated IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.lastupdated);",
    f"CREATE INDEX prowler_finding_status IF NOT EXISTS FOR (n:{PROWLER_FINDING_LABEL}) ON (n.status);",
    # Internet node index for MERGE lookups
    f"CREATE INDEX internet_id IF NOT EXISTS FOR (n:{INTERNET_NODE_LABEL}) ON (n.id);",
]

# Indexes for provider resource sync operations
SYNC_INDEX_STATEMENTS = [
    f"CREATE INDEX provider_element_id IF NOT EXISTS FOR (n:{PROVIDER_RESOURCE_LABEL}) ON (n._provider_element_id);",
    f"CREATE INDEX provider_resource_provider_id IF NOT EXISTS FOR (n:{PROVIDER_RESOURCE_LABEL}) ON (n._provider_id);",
    f"CREATE INDEX deprecated_provider_element_id IF NOT EXISTS FOR (n:{DEPRECATED_PROVIDER_RESOURCE_LABEL}) ON (n.provider_element_id);",
    f"CREATE INDEX deprecated_provider_resource_provider_id IF NOT EXISTS FOR (n:{DEPRECATED_PROVIDER_RESOURCE_LABEL}) ON (n.provider_id);",
]


def create_indexes(neo4j_session: neo4j.Session, index_type: IndexType) -> None:
    """
    Create indexes for the specified type.

    Args:
        `neo4j_session`: The Neo4j session to use
        `index_type`: The type of indexes to create (FINDINGS or SYNC)
    """
    if index_type == IndexType.FINDINGS:
        logger.info("Creating indexes for Prowler Findings node types")
        for statement in FINDINGS_INDEX_STATEMENTS:
            run_write_query(neo4j_session, statement)

    elif index_type == IndexType.SYNC:
        logger.info("Ensuring ProviderResource indexes exist")
        for statement in SYNC_INDEX_STATEMENTS:
            neo4j_session.run(statement)


def create_all_indexes(neo4j_session: neo4j.Session) -> None:
    """Create all indexes (both findings and sync)."""
    create_indexes(neo4j_session, IndexType.FINDINGS)
    create_indexes(neo4j_session, IndexType.SYNC)
