from pathlib import Path
from shutil import rmtree

from celery import chain, shared_task
from celery.utils.log import get_task_logger
from config.celery import RLSTask
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE, DJANGO_TMP_OUTPUT_DIRECTORY
from django_celery_beat.models import PeriodicTask
from tasks.jobs.connection import check_provider_connection
from tasks.jobs.deletion import delete_provider, delete_tenant
from tasks.jobs.export import (
    OUTPUT_FORMATS_MAPPING,
    _compress_output_files,
    _generate_output_directory,
    _upload_to_s3,
)
from tasks.jobs.scan import aggregate_findings, perform_prowler_scan
from tasks.utils import batched, get_next_execution_datetime

from api.db_utils import rls_transaction
from api.decorators import set_tenant
from api.models import Finding, Provider, Scan, ScanSummary, StateChoices
from api.utils import initialize_prowler_provider
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)


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


@shared_task(base=RLSTask, name="provider-deletion", queue="deletion")
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
    result = perform_prowler_scan(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        checks_to_execute=checks_to_execute,
    )

    chain(
        perform_scan_summary_task.si(tenant_id, scan_id),
        generate_outputs.si(
            scan_id=scan_id, provider_id=provider_id, tenant_id=tenant_id
        ),
    ).apply_async()

    return result


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
        periodic_task_instance = PeriodicTask.objects.get(
            name=f"scan-perform-scheduled-{provider_id}"
        )
        next_scan_datetime = get_next_execution_datetime(task_id, provider_id)
        scan_instance, _ = Scan.objects.get_or_create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state__in=(StateChoices.SCHEDULED, StateChoices.AVAILABLE),
            scheduler_task_id=periodic_task_instance.id,
            defaults={"state": StateChoices.SCHEDULED},
        )

        scan_instance.task_id = task_id
        scan_instance.save()

    try:
        result = perform_prowler_scan(
            tenant_id=tenant_id,
            scan_id=str(scan_instance.id),
            provider_id=provider_id,
        )
    except Exception as e:
        raise e
    finally:
        with rls_transaction(tenant_id):
            Scan.objects.get_or_create(
                tenant_id=tenant_id,
                name="Daily scheduled scan",
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.SCHEDULED,
                scheduled_at=next_scan_datetime,
                scheduler_task_id=periodic_task_instance.id,
            )

    chain(
        perform_scan_summary_task.si(tenant_id, scan_instance.id),
        generate_outputs.si(
            scan_id=str(scan_instance.id), provider_id=provider_id, tenant_id=tenant_id
        ),
    ).apply_async()

    return result


@shared_task(name="scan-summary")
def perform_scan_summary_task(tenant_id: str, scan_id: str):
    return aggregate_findings(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="tenant-deletion", queue="deletion")
def delete_tenant_task(tenant_id: str):
    return delete_tenant(pk=tenant_id)


@shared_task(
    base=RLSTask,
    name="scan-report",
    queue="scan-reports",
)
@set_tenant(keep_tenant=True)
def generate_outputs(scan_id: str, provider_id: str, tenant_id: str):
    """
    Process findings in batches and generate output files in multiple formats.

    This function retrieves findings associated with a scan, processes them
    in batches of 50, and writes each batch to the corresponding output files.
    It reuses output writer instances across batches, updates them with each
    batch of transformed findings, and uses a flag to indicate when the final
    batch is being processed. Finally, the output files are compressed and
    uploaded to S3.

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
        provider_id (str): The provider_id id to be used in generating outputs.
    """
    # Initialize the prowler provider
    prowler_provider = initialize_prowler_provider(Provider.objects.get(id=provider_id))

    # Get the provider UID
    provider_uid = Provider.objects.get(id=provider_id).uid

    # Generate and ensure the output directory exists
    output_directory = _generate_output_directory(
        DJANGO_TMP_OUTPUT_DIRECTORY, provider_uid, tenant_id, scan_id
    )

    # Define auxiliary variables
    output_writers = {}
    scan_summary = FindingOutput._transform_findings_stats(
        ScanSummary.objects.filter(scan_id=scan_id)
    )

    # Retrieve findings queryset
    findings_qs = Finding.all_objects.filter(scan_id=scan_id).order_by("uid")

    # Process findings in batches
    for batch, is_last_batch in batched(
        findings_qs.iterator(), DJANGO_FINDINGS_BATCH_SIZE
    ):
        finding_outputs = [
            FindingOutput.transform_api_finding(finding, prowler_provider)
            for finding in batch
        ]

        # Generate output files
        for mode, config in OUTPUT_FORMATS_MAPPING.items():
            kwargs = dict(config.get("kwargs", {}))
            if mode == "html":
                kwargs["provider"] = prowler_provider
                kwargs["stats"] = scan_summary

            writer_class = config["class"]
            if writer_class in output_writers:
                writer = output_writers[writer_class]
                writer.transform(finding_outputs)
                writer.close_file = is_last_batch
            else:
                writer = writer_class(
                    findings=finding_outputs,
                    file_path=output_directory,
                    file_extension=config["suffix"],
                    from_cli=False,
                )
                writer.close_file = is_last_batch
                output_writers[writer_class] = writer

            # Write the current batch using the writer
            writer.batch_write_data_to_file(**kwargs)

            # TODO: Refactor the output classes to avoid this manual reset
            writer._data = []

    # Compress output files
    output_directory = _compress_output_files(output_directory)

    # Save to configured storage
    uploaded = _upload_to_s3(tenant_id, output_directory, scan_id)

    if uploaded:
        output_directory = uploaded
        uploaded = True
        # Remove the local files after upload
        rmtree(Path(output_directory).parent, ignore_errors=True)
    else:
        uploaded = False

    # Update the scan instance with the output path
    Scan.all_objects.filter(id=scan_id).update(output_location=output_directory)

    logger.info(f"Scan output files generated, output location: {output_directory}")

    return {"upload": uploaded}
