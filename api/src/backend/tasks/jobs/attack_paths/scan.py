import logging
import time
import asyncio

from typing import Any

from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from api.db_utils import rls_transaction
from django.db.models import Subquery
from api.models import (
    Provider as ProwlerAPIProvider,
    Scan as ProwlerAPIScan,
    StateChoices,
)
from api.utils import initialize_prowler_provider
from tasks.jobs.attack_paths import aws, db_utils, prowler, utils

# Without this Celery goes crazy with Cartography logging
logging.getLogger("cartography").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

logger = get_task_logger(__name__)

CARTOGRAPHY_INGESTION_FUNCTIONS = {
    "aws": aws.start_aws_ingestion,
}


def run(tenant_id: str, scan_id: str, task_id: str) -> dict[str, Any]:
    """
    Code based on Cartography version 0.117.0, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
    `cartography.sync.run_with_config` and `cartography.sync.Sync.run`.
    """
    ingestion_exceptions = {}  # This will hold any exceptions raised during ingestion

    # Prowler necessary objects
    with rls_transaction(tenant_id):
        provider_id_subquery = ProwlerAPIScan.objects.filter(pk=scan_id).values(
            "provider_id"
        )[:1]
        prowler_api_provider = ProwlerAPIProvider.objects.get(
            id=Subquery(provider_id_subquery)
        )
        prowler_sdk_provider = initialize_prowler_provider(prowler_api_provider)

    # If the provider is still not supported, just return the current `ingestion_exceptions`, that is empty
    if prowler_api_provider.provider not in CARTOGRAPHY_INGESTION_FUNCTIONS:
        return ingestion_exceptions

    # Attributes `neo4j_user` and `neo4j_password` are not really needed in this config object
    cartography_config = CartographyConfig(
        neo4j_uri=graph_database.get_uri(),
        neo4j_database=graph_database.get_tenant_database_name(
            str(prowler_api_provider.tenant_id)
        ),
        update_tag=int(time.time()),
    )

    attack_paths_scan = db_utils.create_attack_paths_scan(
        tenant_id, scan_id, task_id, prowler_api_provider.id, cartography_config
    )

    try:
        logger.info(
            f"Creating Neo4j database {cartography_config.neo4j_database} for tenant {prowler_api_provider.tenant_id}"
        )
        graph_database.create_database(cartography_config.neo4j_database)
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 1)

        logger.info(
            f"Starting Cartography ({attack_paths_scan.id}) for "
            f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )
        with graph_database.get_session(
            cartography_config.neo4j_database
        ) as neo4j_session:
            # Indexes creation
            cartography_create_indexes.run(neo4j_session, cartography_config)
            prowler.create_indexes(neo4j_session)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 2)

            # The real scan, where iterates over cloud services
            ingestion_exceptions = _call_within_event_loop(
                CARTOGRAPHY_INGESTION_FUNCTIONS[prowler_api_provider.provider],
                neo4j_session,
                cartography_config,
                prowler_api_provider,
                prowler_sdk_provider,
                attack_paths_scan,
            )

            # Post-processing: Just keeping it to be more Cartography compliant
            cartography_analysis.run(neo4j_session, cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 95)

            # Adding Prowler nodes and relationships
            prowler.analysis(neo4j_session, prowler_api_provider, cartography_config)

        logger.info(
            f"Completed Cartography ({attack_paths_scan.id}) for "
            f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )
        db_utils.finish_attack_paths_scan(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_exceptions
        )
        return ingestion_exceptions

    except Exception as e:
        exception_message = utils.stringify_exception(e, "Cartography failed")
        logger.error(exception_message)
        ingestion_exceptions["global_cartography_error"] = exception_message

        db_utils.finish_attack_paths_scan(
            attack_paths_scan, StateChoices.FAILED, ingestion_exceptions
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
