from celery.utils.log import get_task_logger
from django.db import DatabaseError, transaction

from api.db_router import MainRouter
from api.db_utils import batch_delete, rls_transaction
from api.models import Finding, Provider, Resource, Scan, ScanSummary, Tenant

logger = get_task_logger(__name__)


def delete_provider(pk: str):
    """
    Gracefully deletes an instance of a provider along with its related data.

    Args:
        pk (str): The primary key of the Provider instance to delete.

    Returns:
        dict: A dictionary with the count of deleted objects per model,
              including related models.

    Raises:
        Provider.DoesNotExist: If no instance with the provided primary key exists.
        DatabaseError: If any deletion step fails.
    """
    instance = Provider.all_objects.get(pk=pk)

    deletion_summary = {}

    deletion_steps = [
        ("Scan Summaries", ScanSummary.all_objects.filter(scan__provider=instance)),
        ("Findings", Finding.all_objects.filter(scan__provider=instance)),
        ("Resources", Resource.all_objects.filter(provider=instance)),
        ("Scans", Scan.all_objects.filter(provider=instance)),
    ]

    for step_name, queryset in deletion_steps:
        try:
            with transaction.atomic():
                _, step_summary = batch_delete(queryset)
                deletion_summary.update(step_summary)
        except DatabaseError as error:
            logger.error(f"Error deleting {step_name}: {error}")
            raise

    # Delete the provider itself
    try:
        with transaction.atomic():
            _, provider_summary = instance.delete()
            deletion_summary.update(provider_summary)
    except DatabaseError as error:
        logger.error(f"Error deleting Provider: {error}")
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
        with rls_transaction(pk):
            summary = delete_provider(provider.id)
            deletion_summary.update(summary)

    Tenant.objects.using(MainRouter.admin_db).filter(id=pk).delete()

    return deletion_summary
