import logging
import time
import asyncio

from typing import Any, Callable

from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from cartography.intel import ontology as cartography_ontology
from celery.utils.log import get_task_logger

from api.attack_paths import database as graph_database
from api.db_utils import rls_transaction
from api.models import (
    Provider as ProwlerAPIProvider,
    StateChoices,
)
from api.utils import initialize_prowler_provider
from tasks.jobs.attack_paths import aws, db_utils, prowler, utils

# Without this Celery goes crazy with Cartography logging
logging.getLogger("cartography").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

logger = get_task_logger(__name__)

CARTOGRAPHY_INGESTION_FUNCTIONS: dict[str, Callable] = {
    "aws": aws.start_aws_ingestion,
}


def get_cartography_ingestion_function(provider_type: str) -> Callable | None:
    return CARTOGRAPHY_INGESTION_FUNCTIONS.get(provider_type)


def run(tenant_id: str, scan_id: str, task_id: str) -> dict[str, Any]:
    """
    Code based on Cartography version 0.122.0, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
    `cartography.sync.run_with_config` and `cartography.sync.Sync.run`.
    """
    ingestion_exceptions = {}  # This will hold any exceptions raised during ingestion

    # Prowler necessary objects
    with rls_transaction(tenant_id):
        prowler_api_provider = ProwlerAPIProvider.objects.get(scan__pk=scan_id)
        prowler_sdk_provider = initialize_prowler_provider(prowler_api_provider)

    # Attack Paths Scan necessary objects
    cartography_ingestion_function = get_cartography_ingestion_function(
        prowler_api_provider.provider
    )
    attack_paths_scan = db_utils.retrieve_attack_paths_scan(tenant_id, scan_id)

    # Checks before starting the scan
    if not cartography_ingestion_function:
        ingestion_exceptions = {
            "global_error": f"Provider {prowler_api_provider.provider} is not supported for Attack Paths scans"
        }
        if attack_paths_scan:
            db_utils.finish_attack_paths_scan(
                attack_paths_scan, StateChoices.COMPLETED, ingestion_exceptions
            )

        logger.warning(
            f"Provider {prowler_api_provider.provider} is not supported for Attack Paths scans"
        )
        return ingestion_exceptions

    else:
        if not attack_paths_scan:
            logger.warning(
                f"No Attack Paths Scan found for scan {scan_id} and tenant {tenant_id}, let's create it then"
            )
            attack_paths_scan = db_utils.create_attack_paths_scan(
                tenant_id, scan_id, prowler_api_provider.id
            )

    # While creating the Cartography configuration, attributes `neo4j_user` and `neo4j_password` are not really needed in this config object
    cartography_config = CartographyConfig(
        neo4j_uri=graph_database.get_uri(),
        neo4j_database=graph_database.get_database_name(attack_paths_scan.id),
        update_tag=int(time.time()),
    )

    # Starting the Attack Paths scan
    db_utils.starting_attack_paths_scan(attack_paths_scan, task_id, cartography_config)

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
                cartography_ingestion_function,
                neo4j_session,
                cartography_config,
                prowler_api_provider,
                prowler_sdk_provider,
                attack_paths_scan,
            )

            # Post-processing: Just keeping it to be more Cartography compliant
            logger.info(
                f"Syncing Cartography ontology for AWS account {prowler_api_provider.uid}"
            )
            cartography_ontology.run(neo4j_session, cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 95)

            logger.info(
                f"Syncing Cartography analysis for AWS account {prowler_api_provider.uid}"
            )
            cartography_analysis.run(neo4j_session, cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 96)

            # Adding Prowler nodes and relationships
            logger.info(
                f"Syncing Prowler analysis for AWS account {prowler_api_provider.uid}"
            )
            prowler.analysis(
                neo4j_session, prowler_api_provider, scan_id, cartography_config
            )

        logger.info(
            f"Clearing Neo4j cache for database {cartography_config.neo4j_database}"
        )
        graph_database.clear_cache(cartography_config.neo4j_database)

        logger.info(
            f"Completed Cartography ({attack_paths_scan.id}) for "
            f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )

        # Handling databases changes
        old_attack_paths_scans = db_utils.get_old_attack_paths_scans(
            prowler_api_provider.tenant_id,
            prowler_api_provider.id,
            attack_paths_scan.id,
        )
        for old_attack_paths_scan in old_attack_paths_scans:
            graph_database.drop_database(old_attack_paths_scan.graph_database)
            db_utils.update_old_attack_paths_scan(old_attack_paths_scan)

        db_utils.finish_attack_paths_scan(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_exceptions
        )
        return ingestion_exceptions

    except Exception as e:
        exception_message = utils.stringify_exception(e, "Cartography failed")
        logger.error(exception_message)
        ingestion_exceptions["global_cartography_error"] = exception_message

        # Handling databases changes
        graph_database.drop_database(cartography_config.neo4j_database)
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

        except Exception as e:
            logger.warning(f"Failed to shutdown async generators cleanly: {e}")

        loop.close()
        asyncio.set_event_loop(None)
