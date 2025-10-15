from celery.utils.log import get_task_logger
from neo4j import GraphDatabase

from tasks.jobs.cartography.aws import sync_aws

logger = get_task_logger(__name__)


def cartography_sync_scan(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
):
    """
    Sync scan data to Cartography.
    """

    logger.info(f"Sync Cartography - Tenant {tenant_id} - Provider {provider_id} - Scan {scan_id}")

    # TODO: Get Neo4j parameters from settings
    with GraphDatabase.driver("bolt://neo4j:7687", auth=("neo4j", "neo4j_password")) as driver:
        with driver.session() as neo4j_session:

            # TODO: Add `cartography.intel.create_indexes.run` here, before `sync_aws`

            return sync_aws(  # TODO: Depending on the provider type use the appropriate sync function
                tenant_id=tenant_id,
                provider_id=provider_id,
                scan_id=scan_id,
                neo4j_session=neo4j_session,
            )

            # TODO: Add `cartography.intel.analysis.run` here, after `sync_aws`
