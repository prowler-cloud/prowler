from datetime import datetime, timedelta, timezone

from celery import shared_task
from config.celery import RLSTask
from django_celery_beat.models import PeriodicTask
from tasks.jobs.connection import check_provider_connection
from tasks.jobs.deletion import delete_provider, delete_tenant
from tasks.jobs.scan import aggregate_findings, perform_prowler_scan

from api.db_utils import rls_transaction
from api.decorators import set_tenant
from api.models import Provider, Scan


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

    It will delete in batches all the related resources first.

    Args:
        provider_id (str): The primary key of the `Provider` instance to be deleted.

    Returns:
        tuple: A tuple containing:
            - The number of instances deleted.
            - A dictionary with the count of deleted instances per model,
              including related models if cascading deletes were triggered.
    """
    return delete_provider(pk=provider_id)


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


@shared_task(base=RLSTask, bind=True, name="scan-perform-scheduled", queue="scans")
def perform_scheduled_scan_task(self, tenant_id: str, provider_id: str):
    """
    Task to perform a scheduled Prowler scan on a given provider.

    This task creates and executes a Prowler scan for the provider identified by `provider_id`
    under the tenant identified by `tenant_id`. It initiates a new scan instance with the task ID
    for tracking purposes. This task is intended to be run on a schedule (e.g., daily) to
    automatically perform scans without manual intervention.

    Args:
        self: The task instance (automatically passed when bind=True).
        tenant_id (str): The tenant ID under which the scan is being performed.
        provider_id (str): The primary key of the Provider instance to scan.

    Returns:
        dict: The result of the scan execution, typically including the status and results
        of the performed checks.

    """
    task_id = self.request.id

    with rls_transaction(tenant_id):
        provider_instance = Provider.objects.get(pk=provider_id)
        periodic_task_instance = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{provider_id}"
        )
        next_scan_date = datetime.combine(
            datetime.now(timezone.utc), periodic_task_instance.start_time.time()
        ) + timedelta(hours=24)

        scan_instance = Scan.objects.create(
            tenant_id=tenant_id,
            name="Daily scheduled scan",
            provider=provider_instance,
            trigger=Scan.TriggerChoices.SCHEDULED,
            next_scan_at=next_scan_date,
            task_id=task_id,
        )

    result = perform_prowler_scan(
        tenant_id=tenant_id,
        scan_id=str(scan_instance.id),
        provider_id=provider_id,
    )
    perform_scan_summary_task.apply_async(
        kwargs={
            "tenant_id": tenant_id,
            "scan_id": str(scan_instance.id),
        }
    )
    return result


@shared_task(name="scan-summary")
def perform_scan_summary_task(tenant_id: str, scan_id: str):
    return aggregate_findings(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="tenant-deletion")
def delete_tenant_task(tenant_id: str):
    return delete_tenant(pk=tenant_id)
