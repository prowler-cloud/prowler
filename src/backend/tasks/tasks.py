from celery import shared_task

from api.decorators import set_tenant
from api.models import Provider
from config.celery import RLSTask
from tasks.jobs.connection import check_provider_connection
from tasks.jobs.deletion import delete_instance


@shared_task(base=RLSTask, name="provider-connection-check")
@set_tenant
def check_provider_connection_task(provider_id: str):
    """
    Task to check the connection status of a provider.

    Args:
        provider_id (str): The primary key of the Provider instance to check.

    Returns:
        dict: A dictionary containing:
            - 'connected' (bool): Indicates whether the provider is successfully connected.
            - 'error' (str or None): The error message if the connection failed, otherwise `None`.
    """
    return check_provider_connection(provider_id)


@shared_task(base=RLSTask, name="provider-deletion")
@set_tenant
def delete_provider_task(provider_id: str):
    """
    Task to delete a specific Provider instance.

    Args:
        provider_id (str): The primary key of the `Provider` instance to be deleted.

    Returns:
        tuple: A tuple containing:
            - The number of instances deleted.
            - A dictionary with the count of deleted instances per model,
              including related models if cascading deletes were triggered.
    """
    return delete_instance(model=Provider, pk=provider_id)
