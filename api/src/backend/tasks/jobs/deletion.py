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
    with rls_transaction(tenant_id):
        instance = Provider.all_objects.get(pk=pk)
        deletion_summary = {}
        deletion_steps = [
            ("Scan Summaries", ScanSummary.all_objects.filter(scan__provider=instance)),
            ("Findings", Finding.all_objects.filter(scan__provider=instance)),
            ("Resources", Resource.all_objects.filter(provider=instance)),
            ("Scans", Scan.all_objects.filter(provider=instance)),
            ("AttackPathsScans", AttackPathsScan.all_objects.filter(provider=instance)),
        ]

    for step_name, queryset in deletion_steps:
        try:
            _, step_summary = batch_delete(tenant_id, queryset)
            deletion_summary.update(step_summary)
        except DatabaseError as db_error:
            logger.error(f"Error deleting {step_name}: {db_error}")
            raise

    # Delete the Attack Paths' Neo4j data related to the provider
    try:
        graph_database.drop_tenant_provider_databases(instance.tenant_id, instance.id)
    except graph_database.GraphDatabaseQueryException as gdb_error:
        logger.error(f"Error deleting Provider subgraph: {gdb_error}")
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

    try:  # If there is any remaining Neo4j database for the tenant
        graph_database.drop_tenant_databases(tenant_id=pk)
    except graph_database.GraphDatabaseQueryException as gdb_error:
        logger.error(f"Error deleting Tenant graph database: {gdb_error}")
        raise

    Tenant.objects.using(MainRouter.admin_db).filter(id=pk).delete()

    return deletion_summary
