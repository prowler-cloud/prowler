"""
Attack Paths scan orchestrator.

Runs the full scan lifecycle for a single provider, called from a Celery task.
The idea is simple: ingest everything into a throwaway Neo4j database, enrich
it with Prowler-specific data, then swap it into the tenant's long-lived
database so queries never see a half-built graph.

Two databases are involved:
- Temporary (db-tmp-scan-<attack_paths_scan_id>): short-lived, single-provider, dropped after sync.
- Tenant (db-tenant-<tenant_uuid>): long-lived, multi-provider, what the API queries against.

Pipeline steps:

1. Resolve the Prowler provider and SDK credentials from the scan ID.
   Retrieve or create the AttackPathsScan row. Exit early if the provider
   type has no ingestion function (only AWS is supported today).

2. Create a fresh temporary Neo4j database and set up Cartography indexes
   plus ProwlerFinding indexes before writing any data.

3. Run the provider-specific Cartography ingestion (e.g. aws.start_aws_ingestion).
   This iterates over cloud services and writes the standard Cartography nodes
   (AWSAccount, EC2Instance, IAMRole, etc.) and relationships (RESOURCE,
   POLICY, STATEMENT, TRUSTS_AWS_PRINCIPAL, ...) into the temp database.
   Wrapped in call_within_event_loop because some Cartography modules use async.

4. Run Cartography post-processing: ontology for label propagation and
   analysis for derived relationships.

5. Create an Internet singleton node and add CAN_ACCESS relationships to
   internet-exposed resources (EC2Instance, LoadBalancer, LoadBalancerV2).

6. Stream Prowler findings from Postgres in batches. Each finding becomes a
   ProwlerFinding node linked to its cloud-resource node via HAS_FINDING.
   Before that, an _AWSResource label (provider-specific) is added to all
   nodes connected to the AWSAccount so finding lookups can use an index.
   Stale findings from previous scans are cleaned up.

7. Sync the temp database into the tenant database:
   - Drop the old provider subgraph (matched by dynamic _Provider_{uuid} label).
     graph_data_ready is set to False for all scans of this provider while
     the swap happens so the API doesn't serve partial data.
   - Copy nodes and relationships in batches. Every synced node gets a
     _ProviderResource label and dynamic _Tenant_{uuid} / _Provider_{uuid}
     isolation labels, plus a _provider_element_id property for MERGE keys.
   - Set graph_data_ready back to True.

8. Drop the temporary database, mark the AttackPathsScan as COMPLETED.

On failure the temp database is dropped, the scan is marked FAILED, and the
exception propagates to Celery.

"""

import logging
import time

from typing import Any

from cartography.config import Config as CartographyConfig
from cartography.intel import analysis as cartography_analysis
from cartography.intel import create_indexes as cartography_create_indexes
from cartography.intel import ontology as cartography_ontology
from celery.utils.log import get_task_logger
from tasks.jobs.attack_paths import db_utils, findings, indexes, internet, sync, utils
from tasks.jobs.attack_paths.config import get_cartography_ingestion_function

from api.attack_paths import database as graph_database
from api.db_utils import rls_transaction
from api.models import Provider as ProwlerAPIProvider
from api.models import StateChoices
from api.utils import initialize_prowler_provider

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

    # Idempotency guard: cleanup may have flipped this row to a terminal state
    # while the message was still in flight. Bail out before touching state.
    if attack_paths_scan and attack_paths_scan.state in (
        StateChoices.FAILED,
        StateChoices.COMPLETED,
        StateChoices.CANCELLED,
    ):
        logger.warning(
            f"Attack Paths scan {attack_paths_scan.id} already in terminal "
            f"state {attack_paths_scan.state}; skipping execution"
        )
        return {}

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
            # Safety net: the dispatcher normally pre-creates this row buit fall back here for in-flight messages or direct task invocations
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
    db_utils.starting_attack_paths_scan(attack_paths_scan, tenant_cartography_config)

    scan_t0 = time.perf_counter()
    logger.info(
        f"Starting Attack Paths scan ({attack_paths_scan.id}) for "
        f"{prowler_api_provider.provider.upper()} provider {prowler_api_provider.id}"
    )

    subgraph_dropped = False
    sync_completed = False
    provider_gated = False

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
            indexes.create_findings_indexes(tmp_neo4j_session)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 2)

            # The real scan, where iterates over cloud services
            t0 = time.perf_counter()
            ingestion_exceptions = utils.call_within_event_loop(
                cartography_ingestion_function,
                tmp_neo4j_session,
                tmp_cartography_config,
                prowler_api_provider,
                prowler_sdk_provider,
                attack_paths_scan,
            )
            logger.info(
                f"Cartography ingestion completed in {time.perf_counter() - t0:.3f}s "
                f"(failed_syncs={len(ingestion_exceptions)})"
            )

            # Post-processing: Just keeping it to be more Cartography compliant
            logger.info(
                f"Syncing Cartography ontology for AWS account {prowler_api_provider.uid}"
            )
            cartography_ontology.run(tmp_neo4j_session, tmp_cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 94)

            logger.info(
                f"Syncing Cartography analysis for AWS account {prowler_api_provider.uid}"
            )
            cartography_analysis.run(tmp_neo4j_session, tmp_cartography_config)
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 95)

            # Creating Internet node and CAN_ACCESS relationships
            logger.info(
                f"Creating Internet graph for AWS account {prowler_api_provider.uid}"
            )
            internet.analysis(
                tmp_neo4j_session, prowler_api_provider, tmp_cartography_config
            )
            db_utils.update_attack_paths_scan_progress(attack_paths_scan, 96)

            # Adding Prowler Finding nodes and relationships
            logger.info(
                f"Syncing Prowler analysis for AWS account {prowler_api_provider.uid}"
            )
            t0 = time.perf_counter()
            labeled_nodes, findings_loaded = findings.analysis(
                tmp_neo4j_session, prowler_api_provider, scan_id, tmp_cartography_config
            )
            logger.info(
                f"Prowler analysis completed in {time.perf_counter() - t0:.3f}s "
                f"(findings={findings_loaded}, labeled_nodes={labeled_nodes})"
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
            indexes.create_findings_indexes(tenant_neo4j_session)
            indexes.create_sync_indexes(tenant_neo4j_session)

        logger.info(f"Deleting existing provider graph in {tenant_database_name}")
        db_utils.set_provider_graph_data_ready(attack_paths_scan, False)
        provider_gated = True

        t0 = time.perf_counter()
        deleted_nodes = graph_database.drop_subgraph(
            database=tenant_database_name,
            provider_id=str(prowler_api_provider.id),
        )
        logger.info(
            f"Deleted existing provider graph in {time.perf_counter() - t0:.3f}s "
            f"(deleted_nodes={deleted_nodes})"
        )
        subgraph_dropped = True
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 98)

        logger.info(
            f"Syncing graph from {tmp_database_name} into {tenant_database_name}"
        )
        t0 = time.perf_counter()
        sync_result = sync.sync_graph(
            source_database=tmp_database_name,
            target_database=tenant_database_name,
            tenant_id=str(prowler_api_provider.tenant_id),
            provider_id=str(prowler_api_provider.id),
        )
        logger.info(
            f"Synced graph in {time.perf_counter() - t0:.3f}s "
            f"(nodes={sync_result['nodes']}, relationships={sync_result['relationships']})"
        )
        sync_completed = True
        db_utils.set_graph_data_ready(attack_paths_scan, True)
        db_utils.update_attack_paths_scan_progress(attack_paths_scan, 99)

        logger.info(f"Clearing Neo4j cache for database {tenant_database_name}")
        graph_database.clear_cache(tenant_database_name)

        logger.info(f"Dropping temporary Neo4j database {tmp_database_name}")
        graph_database.drop_database(tmp_database_name)

        db_utils.finish_attack_paths_scan(
            attack_paths_scan, StateChoices.COMPLETED, ingestion_exceptions
        )
        logger.info(
            f"Attack Paths scan completed in {time.perf_counter() - scan_t0:.3f}s "
            f"(state=completed, failed_syncs={len(ingestion_exceptions)})"
        )
        return ingestion_exceptions

    except Exception as e:
        exception_message = utils.stringify_exception(e, "Attack Paths scan failed")
        logger.exception(exception_message)
        ingestion_exceptions["global_error"] = exception_message

        # Recover graph_data_ready based on how far the swap got.
        # Partial drop (mid-batch failure) may leave `subgraph_dropped=False`
        # with data partially deleted, so we prefer that over permanently blocked queries.
        try:
            if sync_completed:
                db_utils.set_graph_data_ready(attack_paths_scan, True)
            elif provider_gated and not subgraph_dropped:
                db_utils.set_provider_graph_data_ready(attack_paths_scan, True)

        except Exception:
            logger.error(
                f"Failed to recover `graph_data_ready` for provider {attack_paths_scan.provider_id}",
                exc_info=True,
            )

        # Dropping the temporary database if it still exists
        try:
            graph_database.drop_database(tmp_cartography_config.neo4j_database)

        except Exception as e:
            logger.error(
                f"Failed to drop temporary Neo4j database `{tmp_cartography_config.neo4j_database}` during cleanup: {e}",
                exc_info=True,
            )

        # Set Attack Paths scan state to FAILED
        try:
            db_utils.finish_attack_paths_scan(
                attack_paths_scan, StateChoices.FAILED, ingestion_exceptions
            )
        except Exception as e:
            logger.error(
                f"Could not mark Attack Paths scan {attack_paths_scan.id} as `FAILED` (row may have been deleted): {e}",
                exc_info=True,
            )

        raise
