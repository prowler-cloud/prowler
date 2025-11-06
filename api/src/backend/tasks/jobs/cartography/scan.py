import time
import asyncio

from django.conf import settings
from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from celery.utils.log import get_task_logger

from api.models import Provider as PrwolerAPIProvider
from api.utils import initialize_prowler_provider
from config import neo4j
from tasks.jobs.cartography import aws, prowler

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger

logger = logging.getLogger(BackendLogger.API)

CARTOGRAPHY_INGESTION_FUNCTIONS = {
    "aws": aws.start_aws_ingestion,
}


def run(provider_id: str) -> None:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
    `cartography.sync.run_with_config` and `cartography.sync.Sync.run`.
    """
    # TODO: Create some object in Postgres to track the Cartography scan status

    prowler_api_provider = PrwolerAPIProvider.objects.get(id=provider_id)
    prowler_provider = initialize_prowler_provider(prowler_api_provider)

    # Attributes `neo4j_user` and `neo4j_password` are not really needed in this config object
    config = CartographyConfig(
        neo4j_uri=neo4j.get_neo4j_uri(),
        neo4j_database=neo4j.get_neo4j_tenant_database_name(str(prowler_api_provider.tenant_id)),
        update_tag=int(time.time()),
    )

    logger.info(f"Create Neo4j database {config.neo4j_database} for tenant {prowler_api_provider.tenant_id}")
    neo4j.create_neo4j_database(config.neo4j_database)

    logger.info(f"Start Cartography scan: {prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}")
    with neo4j.get_neo4j_session(config.neo4j_database) as neo4j_session:
        cartography_create_indexes.run(neo4j_session, config)
        prowler.create_indexes(neo4j_session)

        failed_ingestion_function_exceptions = _call_within_event_loop(
            CARTOGRAPHY_INGESTION_FUNCTIONS[prowler_api_provider.provider],
            neo4j_session,
            config,
            prowler_api_provider,
            prowler_provider,
        )

        # TODO: Check if it's ok to skip this step because we are not configuring it
        if not failed_ingestion_function_exceptions:
            cartography_analysis.run(neo4j_session, config)

        prowler.analysis(neo4j_session, prowler_api_provider, config)

    logger.info(f"Done Cartography scan: {prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}")

    # TODO: Store something in Postgres and set the right task status
    return failed_ingestion_function_exceptions


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
