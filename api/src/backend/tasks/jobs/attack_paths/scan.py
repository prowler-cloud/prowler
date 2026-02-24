import logging
import time

from typing import Any

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
from tasks.jobs.attack_paths import db_utils, findings, internet, sync, utils
from tasks.jobs.attack_paths.config import get_cartography_ingestion_function

# Without this Celery goes crazy with Cartography logging
logging.getLogger("cartography").setLevel(logging.ERROR)
logging.getLogger("neo4j").propagate = False

logger = get_task_logger(__name__)


def run(tenant_id: str, scan_id: str, task_id: str) -> dict[str, Any]:
    """
    Code based on Cartography, specifically on `cartography.cli.main`, `cartography.cli.CLI.main`,
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

    tmp_database_name = graph_database.get_database_name(
        attack_paths_scan.id, temporary=True
    )
    tenant_database_name = graph_database.get_database_name(
        prowler_api_provider.tenant_id
    )

    # While creating the Cartography configuration, attributes `neo4j_user` and `neo4j_password` are not really needed in this config object
    tmp_cartography_config = CartographyConfig(
        neo4j_uri=graph_database.get_uri(),
        neo4j_database=tmp_database_name,
        update_tag=int(time.time()),
    )
    tenant_cartography_config = CartographyConfig(
        neo4j_uri=tmp_cartography_config.neo4j_uri,
        neo4j_database=tenant_database_name,
        update_tag=tmp_cartography_config.update_tag,
    )

    # Starting the Attack Paths scan
    db_utils.starting_attack_paths_scan(
        attack_paths_scan, task_id, tenant_cartography_config
    )

    try:
        logger.info(
            f"Creating Neo4j database {tmp_cartography_config.neo4j_database} for tenant {prowler_api_provider.tenant_id}"
        )

        graph_database.create_database(tmp_cartography_config.neo4j_database)
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 1)

        logger.info(
            f"Starting Cartography ({attack_paths_scan.id}) for "
            f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )
        with graph_database.get_session(
            tmp_cartography_config.neo4j_database
        ) as tmp_neo4j_session:
            # Indexes creation
            cartography_create_indexes.run(tmp_neo4j_session, tmp_cartography_config)
            findings.create_findings_indexes(tmp_neo4j_session)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 2)

            # The real scan, where iterates over cloud services
            ingestion_exceptions = utils.call_within_event_loop(
                cartography_ingestion_function,
                tmp_neo4j_session,
                tmp_cartography_config,
                prowler_api_provider,
                prowler_sdk_provider,
                attack_paths_scan,
            )

            # Post-processing: Just keeping it to be more Cartography compliant
            logger.info(
                f"Syncing Cartography ontology for AWS account {prowler_api_provider.uid}"
            )
            cartography_ontology.run(tmp_neo4j_session, tmp_cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 95)

            logger.info(
                f"Syncing Cartography analysis for AWS account {prowler_api_provider.uid}"
            )
            cartography_analysis.run(tmp_neo4j_session, tmp_cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 96)

            # Creating Internet node and CAN_ACCESS relationships
            logger.info(
                f"Creating Internet graph for AWS account {prowler_api_provider.uid}"
            )
            internet.analysis(
                tmp_neo4j_session, prowler_api_provider, tmp_cartography_config
            )

            # Adding Prowler Finding nodes and relationships
            logger.info(
                f"Syncing Prowler analysis for AWS account {prowler_api_provider.uid}"
            )
            findings.analysis(
                tmp_neo4j_session, prowler_api_provider, scan_id, tmp_cartography_config
            )
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 97)

        logger.info(
            f"Clearing Neo4j cache for database {tmp_cartography_config.neo4j_database}"
        )
        graph_database.clear_cache(tmp_cartography_config.neo4j_database)

        logger.info(
            f"Ensuring tenant database {tenant_database_name}, and its indexes, exists for tenant {prowler_api_provider.tenant_id}"
        )
        graph_database.create_database(tenant_database_name)
        with graph_database.get_session(tenant_database_name) as tenant_neo4j_session:
            cartography_create_indexes.run(
                tenant_neo4j_session, tenant_cartography_config
            )
            findings.create_findings_indexes(tenant_neo4j_session)
            sync.create_sync_indexes(tenant_neo4j_session)

        logger.info(f"Deleting existing provider graph in {tenant_database_name}")
        db_utils.set_provider_graph_data_ready(attack_paths_scan, False)
        graph_database.drop_subgraph(
            database=tenant_database_name,
            provider_id=str(prowler_api_provider.id),
        )
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 98)

        logger.info(
            f"Syncing graph from {tmp_database_name} into {tenant_database_name}"
        )
        sync.sync_graph(
            source_database=tmp_database_name,
            target_database=tenant_database_name,
            provider_id=str(prowler_api_provider.id),
        )
        db_utils.set_graph_data_ready(attack_paths_scan, True)
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 99)

        logger.info(f"Clearing Neo4j cache for database {tenant_database_name}")
        graph_database.clear_cache(tenant_database_name)

        logger.info(
            f"Completed Cartography ({attack_paths_scan.id}) for "
            f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
        )

        logger.info(f"Dropping temporary Neo4j database {tmp_database_name}")
        graph_database.drop_database(tmp_database_name)

        db_utils.finish_attack_paths_scan(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_exceptions
        )
        return ingestion_exceptions

    except Exception as e:
        exception_message = utils.stringify_exception(e, "Attack Paths scan failed")
        logger.exception(exception_message)
        ingestion_exceptions["global_error"] = exception_message

        # Handling databases changes
        try:
            graph_database.drop_database(tmp_cartography_config.neo4j_database)

        except Exception:
            logger.error(
                f"Failed to drop temporary Neo4j database {tmp_cartography_config.neo4j_database} during cleanup"
            )

        try:
            db_utils.finish_attack_paths_scan(
                attack_paths_scan, StateChoices.FAILED, ingestion_exceptions
            )
        except Exception:
            logger.warning(
                f"Could not mark attack paths scan {attack_paths_scan.id} as FAILED (row may have been deleted)"
            )

        raise
