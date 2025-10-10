from celery.utils.log import get_task_logger
from neo4j import GraphDatabase

from tasks.jobs.cartography.aws import sync_aws

logger = get_task_logger(__name__)


def sync_scan_to_cartography(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
):
    """
    Sync scan data to Cartography.
    """

    logger.info(f"Sync Cartography - Tenant {tenant_id} - Provider {provider_id} - Scan {scan_id}")

    # TODO: Get Neo4j parameters from settings
    with GraphDatabase.driver("bolt://neo4j:7687", auth=("neo4j", "neo4j")) as driver:
        with driver.session() as neo4j_session:
            # TODO: Depending on the provider type use the appropriate sync function
            return sync_aws(
                tenant_id=tenant_id,
                provider_id=provider_id,
                scan_id=scan_id,
                neo4j_session=neo4j_session,
            )
