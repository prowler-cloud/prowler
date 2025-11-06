import time
import asyncio

from typing import Any

from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from celery.utils.log import get_task_logger

from api.models import (
    Provider as ProwlerAPIProvider,
    Scan as ProwlerAPIScan,
    StateChoices,
)
from api.utils import initialize_prowler_provider
from config import neo4j
from tasks.jobs.cartography import aws, db_utils, prowler

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger

logger = logging.getLogger(BackendLogger.API)

CARTOGRAPHY_INGESTION_FUNCTIONS = {
    "aws": aws.start_aws_ingestion,
}


def run(scan_id: str) -> dict[str, Any]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
    `cartography.sync.run_with_config` and `cartography.sync.Sync.run`.
    """

    # Attributes `neo4j_user` and `neo4j_password` are not really needed in this config object
    config = CartographyConfig(
        neo4j_uri=neo4j.get_neo4j_uri(),
        neo4j_database=neo4j.get_neo4j_tenant_database_name(
            str(prowler_api_provider.tenant_id)
        ),
        update_tag=int(time.time()),
    )

    # Prowler necessary objects
    prowler_api_scan = ProwlerAPIScan.objects.get(id=scan_id)
    prowler_api_provider = ProwlerAPIProvider.objects.get(
        id=prowler_api_scan.provider_id
    )
    prowler_provider = initialize_prowler_provider(prowler_api_provider)
    cartography_scan = db_utils.create_cartography_scan(
        prowler_api_scan, prowler_api_provider, config
    )

    ingestion_exceptions = {}
    try:
        logger.info(
            f"Create Neo4j database {config.neo4j_database} for tenant {prowler_api_provider.tenant_id}"
        )
        neo4j.create_neo4j_database(config.neo4j_database)
        db_utils.update_cartography_scan_progress(cartography_scan, 1)

        logger.info(
            f"Start Cartography scan: {prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )
        with neo4j.get_neo4j_session(config.neo4j_database) as neo4j_session:
            # Indexes creation
            cartography_create_indexes.run(neo4j_session, config)
            prowler.create_indexes(neo4j_session)
            db_utils.update_cartography_scan_progress(cartography_scan, 2)

            # The real scan, where iterates over cloud services
            ingestion_exceptions = _call_within_event_loop(
                CARTOGRAPHY_INGESTION_FUNCTIONS[prowler_api_provider.provider],
                neo4j_session,
                config,
                prowler_api_provider,
                prowler_provider,
            )

            # Post-processing
            cartography_analysis.run(
                neo4j_session, config
            )  # Just keeping it to be more Cartography compliant
            db_utils.update_cartography_scan_progress(cartography_scan, 95)

            # Adding Prowler nodes and relationships
            prowler.analysis(neo4j_session, prowler_api_provider, config)

        logger.info(
            f"Done Cartography scan: {prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )
        db_utils.modify_cartography_scan(
            cartography_scan, StateChoices.COMPLETED, ingestion_exceptions
        )
        return ingestion_exceptions

    except Exception as e:
        logger.error(f"Cartography scan failed: {e}")
        ingestion_exceptions["global_cartography_scan_error"] = str(e)
        db_utils.modify_cartography_scan(
            cartography_scan, StateChoices.FAILED, ingestion_exceptions
        )
        raise


def _call_within_event_loop(fn, *args, **kwargs):
    """
    Cartography needs a running event loop, so assuming there is none (Celery task or even regular DRF endpoint),
    let's create a new one and set it as the current event loop for this thread.
    """

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return fn(*args, **kwargs)

    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())

        except Exception:
            pass

        loop.close()
        asyncio.set_event_loop(None)
