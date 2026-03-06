from celery.utils.log import get_task_logger
from django.db import DatabaseError
from tasks.jobs.queries import (
    COMPLIANCE_DELETE_EMPTY_TENANT_SUMMARY_SQL,
    COMPLIANCE_UPSERT_TENANT_SUMMARY_SQL,
)

from api.attack_paths import database as graph_database
from api.db_router import MainRouter
from api.db_utils import batch_delete, rls_transaction
from api.models import (
    AttackPathsScan,
    Finding,
    Provider,
    ProviderComplianceScore,
    Resource,
    Scan,
    ScanSummary,
    Tenant,
)

logger = get_task_logger(__name__)


def _recalculate_tenant_compliance_summary(tenant_id: str, compliance_ids: list[str]):
    if not compliance_ids:
        return

    compliance_ids = sorted(set(compliance_ids))

    with rls_transaction(tenant_id, using=MainRouter.default_db) as cursor:
        # Serialize tenant-level summary updates to avoid concurrent recomputes
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtext(%s))",
            [tenant_id],
        )
        cursor.execute(
            COMPLIANCE_UPSERT_TENANT_SUMMARY_SQL,
            [tenant_id, tenant_id, compliance_ids],
        )
        cursor.execute(
            COMPLIANCE_DELETE_EMPTY_TENANT_SUMMARY_SQL,
            [tenant_id, compliance_ids],
        )


def delete_provider(tenant_id: str, pk: str):
    """
    Gracefully deletes an instance of a provider along with its related data.

    Args:
        tenant_id (str): Tenant ID the resources belong to.
        pk (str): The primary key of the Provider instance to delete.

    Returns:
        dict: A dictionary with the count of deleted objects per model,
              including related models. Returns an empty dict if the provider
              was already deleted.
    """

    # Get all provider related data to delete them in batches
    with rls_transaction(tenant_id):
        try:
            instance = Provider.all_objects.get(pk=pk)
        except Provider.DoesNotExist:
            logger.info(f"Provider `{pk}` already deleted, skipping")
            return {}

        compliance_ids = list(
            ProviderComplianceScore.objects.filter(provider=instance)
            .values_list("compliance_id", flat=True)
            .distinct()
        )

        attack_paths_scan_ids = list(
            AttackPathsScan.all_objects.filter(provider=instance).values_list(
                "id", flat=True
            )
        )

        deletion_steps = [
            ("Scan Summaries", ScanSummary.all_objects.filter(scan__provider=instance)),
            ("Findings", Finding.all_objects.filter(scan__provider=instance)),
            ("Resources", Resource.all_objects.filter(provider=instance)),
            ("Scans", Scan.all_objects.filter(provider=instance)),
            ("AttackPathsScans", AttackPathsScan.all_objects.filter(provider=instance)),
        ]

    # Drop orphaned temporary Neo4j databases
    for aps_id in attack_paths_scan_ids:
        tmp_db_name = graph_database.get_database_name(aps_id, temporary=True)
        try:
            graph_database.drop_database(tmp_db_name)

        except graph_database.GraphDatabaseQueryException:
            logger.warning(f"Failed to drop temp database {tmp_db_name}, continuing")

    # Delete the Attack Paths' graph data related to the provider from the tenant database
    tenant_database_name = graph_database.get_database_name(tenant_id)
    try:
        graph_database.drop_subgraph(tenant_database_name, str(pk))

    except graph_database.GraphDatabaseQueryException as gdb_error:
        logger.error(f"Error deleting Provider graph data: {gdb_error}")
        raise

    # Delete related data in batches
    deletion_summary = {}
    for step_name, queryset in deletion_steps:
        try:
            _, step_summary = batch_delete(tenant_id, queryset)
            deletion_summary.update(step_summary)
        except DatabaseError as db_error:
            logger.error(f"Error deleting {step_name}: {db_error}")
            raise

    # Delete the provider instance itself
    try:
        with rls_transaction(tenant_id):
            _, provider_summary = instance.delete()
        deletion_summary.update(provider_summary)
    except DatabaseError as db_error:
        logger.error(f"Error deleting Provider: {db_error}")
        raise

    try:
        _recalculate_tenant_compliance_summary(tenant_id, compliance_ids)
    except Exception as db_error:
        logger.error(
            "Error recalculating tenant compliance summary after provider delete: %s",
            db_error,
        )
        raise

    return deletion_summary


def delete_tenant(pk: str):
    """
    Gracefully deletes an instance of a tenant along with its related data.

    Args:
        pk (str): The primary key of the Tenant instance to delete.

    Returns:
        dict: A dictionary with the count of deleted objects per model,
              including related models.
    """
    deletion_summary = {}

    for provider in Provider.all_objects.using(MainRouter.admin_db).filter(
        tenant_id=pk
    ):
        summary = delete_provider(pk, provider.id)
        deletion_summary.update(summary)

    try:
        tenant_database_name = graph_database.get_database_name(pk)
        graph_database.drop_database(tenant_database_name)
    except graph_database.GraphDatabaseQueryException as gdb_error:
        logger.error(f"Error dropping Tenant graph database: {gdb_error}")
        raise

    Tenant.objects.using(MainRouter.admin_db).filter(id=pk).delete()

    return deletion_summary
