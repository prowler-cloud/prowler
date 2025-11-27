from celery.utils.log import get_task_logger
from django.db import DatabaseError

from api.attack_paths import database as graph_database
from api.db_router import MainRouter
from api.db_utils import batch_delete, rls_transaction
from api.models import (
    AttackPathsScan,
    Finding,
    Provider,
    Resource,
    Scan,
    ScanSummary,
    Tenant,
)
from tasks.jobs.attack_paths.db_utils import get_provider_graph_database_names

logger = get_task_logger(__name__)


def delete_provider(tenant_id: str, pk: str):
    """
    Gracefully deletes an instance of a provider along with its related data.

    Args:
        tenant_id (str): Tenant ID the resources belong to.
        pk (str): The primary key of the Provider instance to delete.

    Returns:
        dict: A dictionary with the count of deleted objects per model,
              including related models.

    Raises:
        Provider.DoesNotExist: If no instance with the provided primary key exists.
    """
    # Delete the Attack Paths' graph databases related to the provider
    graph_database_names = get_provider_graph_database_names(tenant_id, pk)
    try:
        for graph_database_name in graph_database_names:
            graph_database.drop_database(graph_database_name)
    except graph_database.GraphDatabaseQueryException as gdb_error:
        logger.error(f"Error deleting Provider databases: {gdb_error}")
        raise

    # Get all provider related data and delete them in batches
    with rls_transaction(tenant_id):
        instance = Provider.all_objects.get(pk=pk)
        deletion_steps = [
            ("Scan Summaries", ScanSummary.all_objects.filter(scan__provider=instance)),
            ("Findings", Finding.all_objects.filter(scan__provider=instance)),
            ("Resources", Resource.all_objects.filter(provider=instance)),
            ("Scans", Scan.all_objects.filter(provider=instance)),
            ("AttackPathsScans", AttackPathsScan.all_objects.filter(provider=instance)),
        ]

    deletion_summary = {}
    for step_name, queryset in deletion_steps:
        try:
            _, step_summary = batch_delete(tenant_id, queryset)
            deletion_summary.update(step_summary)
        except DatabaseError as db_error:
            logger.error(f"Error deleting {step_name}: {db_error}")
            raise

    try:
        with rls_transaction(tenant_id):
            _, provider_summary = instance.delete()
        deletion_summary.update(provider_summary)
    except DatabaseError as db_error:
        logger.error(f"Error deleting Provider: {db_error}")
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

    for provider in Provider.objects.using(MainRouter.admin_db).filter(tenant_id=pk):
        summary = delete_provider(pk, provider.id)
        deletion_summary.update(summary)

    Tenant.objects.using(MainRouter.admin_db).filter(id=pk).delete()

    return deletion_summary
