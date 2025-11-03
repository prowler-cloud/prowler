import time
import asyncio

import neo4j

from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from celery.utils.log import get_task_logger

from api.models import Provider as PrwolerAPIProvider
from api.utils import initialize_prowler_provider
from tasks.jobs.cartography.aws import start_aws_ingestion
from tasks.jobs.cartography import prowler

# TODO: Use the right logger
# logger = get_task_logger(__name__)
import logging
from config.custom_logging import BackendLogger

logger = logging.getLogger(BackendLogger.API)


CARTOGRAPHY_INGESTION_FUNCTIONS = {
    "aws": start_aws_ingestion,
}


def run(provider_id: str) -> None:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
    `cartography.sync.run_with_config` and `cartography.sync.Sync.run`.
    """

    provider_api_provider = PrwolerAPIProvider.objects.get(id=provider_id)
    prowler_provider = initialize_prowler_provider(provider_api_provider)

    # TODO: Proper Neo4j configuration
    neo4j_uri = "bolt://neo4j:7687"
    neo4j_user = "neo4j"
    neo4j_password = "neo4j_password"

    config = CartographyConfig(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,  # TODO: Don't needed, just for consistency with `neo4j_uri`
        neo4j_password=neo4j_password,  # TODO: Don't needed, just for consistency with `neo4j_uri`
        update_tag=int(time.time()),
    )

    logger.info(
        f"Starting Cartography scan for provider {provider_api_provider.provider.upper()} {provider_api_provider.id}"
    )

    # TODO: Manage Neo4j database as we need to check if the database exist and create it if not

    with neo4j.GraphDatabase.driver(
        neo4j_uri, auth=(neo4j_user, neo4j_password)
    ) as driver:
        with driver.session() as neo4j_session:
            cartography_create_indexes.run(neo4j_session, config)
            prowler.create_indexes(neo4j_session)

            failed_ingestion_function_exceptions = _call_within_event_loop(
                CARTOGRAPHY_INGESTION_FUNCTIONS[provider_api_provider.provider],
                neo4j_session,
                config,
                provider_api_provider,
                prowler_provider,
            )

            # TODO: Check if it's ok to skip this step because we are not configuring it
            if not failed_ingestion_function_exceptions:
                cartography_analysis.run(neo4j_session, config)

            prowler.analysis(neo4j_session, provider_api_provider, config)

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
