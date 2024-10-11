from celery import shared_task

from api.decorators import set_tenant
from api.models import Provider
from config.celery import RLSTask
from tasks.jobs.connection import check_provider_connection
from tasks.jobs.deletion import delete_instance
from tasks.jobs.scan import perform_prowler_scan


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
    return check_provider_connection(provider_id=provider_id)


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


@shared_task(base=RLSTask, name="scan-perform", queue="scans")
def perform_scan_task(
    tenant_id: str, scan_id: str, provider_id: str, checks_to_execute: list[str] = None
):
    """
    Task to perform a Prowler scan on a given provider.

    This task runs a Prowler scan on the provider identified by `provider_id`
    under the tenant identified by `tenant_id`. The scan will use the `scan_id`
    for tracking purposes.

    Args:
        tenant_id (str): The tenant ID under which the scan is being performed.
        scan_id (str): The ID of the scan to be performed.
        provider_id (str): The primary key of the Provider instance to scan.
        checks_to_execute (list[str], optional): A list of specific checks to perform during the scan. Defaults to None.

    Returns:
        dict: The result of the scan execution, typically including the status and results of the performed checks.
    """
    return perform_prowler_scan(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        checks_to_execute=checks_to_execute,
    )
