import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from shutil import rmtree

from celery import chain, group, shared_task
from celery.utils.log import get_task_logger
from config.celery import RLSTask
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE, DJANGO_TMP_OUTPUT_DIRECTORY
from django_celery_beat.models import PeriodicTask
from tasks.jobs.attack_paths import (
    attack_paths_scan,
    can_provider_run_attack_paths_scan,
    db_utils as attack_paths_db_utils,
)
from tasks.jobs.backfill import (
    backfill_compliance_summaries,
    backfill_daily_severity_summaries,
    backfill_provider_compliance_scores,
    backfill_resource_scan_summaries,
    backfill_scan_category_summaries,
    backfill_scan_resource_group_summaries,
)
from tasks.jobs.connection import (
    check_integration_connection,
    check_lighthouse_connection,
    check_provider_connection,
)
from tasks.jobs.deletion import delete_provider, delete_tenant
from tasks.jobs.export import (
    COMPLIANCE_CLASS_MAP,
    OUTPUT_FORMATS_MAPPING,
    _compress_output_files,
    _generate_output_directory,
    _upload_to_s3,
)
from tasks.jobs.integrations import (
    send_findings_to_jira,
    upload_s3_integration,
    upload_security_hub_integration,
)
from tasks.jobs.lighthouse_providers import (
    check_lighthouse_provider_connection,
    refresh_lighthouse_provider_models,
)
from tasks.jobs.muting import mute_historical_findings
from tasks.jobs.report import generate_compliance_reports_job
from tasks.jobs.scan import (
    aggregate_attack_surface,
    aggregate_daily_severity,
    aggregate_findings,
    create_compliance_requirements,
    perform_prowler_scan,
    update_provider_compliance_scores,
)
from tasks.utils import (
    _get_or_create_scheduled_scan,
    batched,
    get_next_execution_datetime,
)

from api.compliance import get_compliance_frameworks
from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.decorators import handle_provider_deletion, set_tenant
from api.models import Finding, Integration, Provider, Scan, ScanSummary, StateChoices
from api.utils import initialize_prowler_provider
from api.v1.serializers import ScanTaskSerializer
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.generic.generic import GenericCompliance
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)


def _cleanup_orphan_scheduled_scans(
    tenant_id: str,
    provider_id: str,
    scheduler_task_id: int,
) -> int:
    """
    TEMPORARY WORKAROUND: Clean up orphan AVAILABLE scans.

    Detects and removes AVAILABLE scans that were never used due to an
    issue during the first scheduled scan setup.

    An AVAILABLE scan is considered orphan if there's also a SCHEDULED scan for
    the same provider with the same scheduler_task_id. This situation indicates
    that the first scan execution didn't find the AVAILABLE scan (because it
    wasn't committed yet, probably) and created a new one, leaving the AVAILABLE orphaned.

    Args:
        tenant_id: The tenant ID.
        provider_id: The provider ID.
        scheduler_task_id: The PeriodicTask ID that triggers these scans.

    Returns:
        Number of orphan scans deleted (0 if none found).
    """
    orphan_available_scans = Scan.objects.filter(
        tenant_id=tenant_id,
        provider_id=provider_id,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.AVAILABLE,
        scheduler_task_id=scheduler_task_id,
    )

    scheduled_scan_exists = Scan.objects.filter(
        tenant_id=tenant_id,
        provider_id=provider_id,
        trigger=Scan.TriggerChoices.SCHEDULED,
        state=StateChoices.SCHEDULED,
        scheduler_task_id=scheduler_task_id,
    ).exists()

    if scheduled_scan_exists and orphan_available_scans.exists():
        orphan_count = orphan_available_scans.count()
        logger.warning(
            f"[WORKAROUND] Found {orphan_count} orphan AVAILABLE scan(s) for "
            f"provider {provider_id} alongside a SCHEDULED scan. Cleaning up orphans..."
        )
        orphan_available_scans.delete()
        return orphan_count

    return 0


def _perform_scan_complete_tasks(tenant_id: str, scan_id: str, provider_id: str):
    """
    Helper function to perform tasks after a scan is completed.

    Args:
        tenant_id (str): The tenant ID under which the scan was performed.
        scan_id (str): The ID of the scan that was performed.
        provider_id (str): The primary key of the Provider instance that was scanned.
    """
    chain(
        create_compliance_requirements_task.si(tenant_id=tenant_id, scan_id=scan_id),
        update_provider_compliance_scores_task.si(tenant_id=tenant_id, scan_id=scan_id),
    ).apply_async()
    aggregate_attack_surface_task.apply_async(
        kwargs={"tenant_id": tenant_id, "scan_id": scan_id}
    )
    chain(
        perform_scan_summary_task.si(tenant_id=tenant_id, scan_id=scan_id),
        group(
            aggregate_daily_severity_task.si(tenant_id=tenant_id, scan_id=scan_id),
            generate_outputs_task.si(
                scan_id=scan_id, provider_id=provider_id, tenant_id=tenant_id
            ),
        ),
        group(
            # Use optimized task that generates both reports with shared queries
            generate_compliance_reports_task.si(
                tenant_id=tenant_id, scan_id=scan_id, provider_id=provider_id
            ),
            check_integrations_task.si(
                tenant_id=tenant_id,
                provider_id=provider_id,
                scan_id=scan_id,
            ),
        ),
    ).apply_async()

    if can_provider_run_attack_paths_scan(tenant_id, provider_id):
        perform_attack_paths_scan_task.apply_async(
            kwargs={"tenant_id": tenant_id, "scan_id": scan_id}
        )


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


@shared_task(base=RLSTask, name="integration-connection-check")
@set_tenant
def check_integration_connection_task(integration_id: str):
    """
    Task to check the connection status of an integration.

    Args:
        integration_id (str): The primary key of the Integration instance to check.
    """
    return check_integration_connection(integration_id=integration_id)


@shared_task(
    base=RLSTask, name="provider-deletion", queue="deletion", autoretry_for=(Exception,)
)
def delete_provider_task(provider_id: str, tenant_id: str):
    """
    Task to delete a specific Provider instance.

    It will delete in batches all the related resources first.

    Args:
        provider_id (str): The primary key of the `Provider` instance to be deleted.
        tenant_id (str): Tenant ID the provider belongs to.

    Returns:
        tuple: A tuple containing:
            - The number of instances deleted.
            - A dictionary with the count of deleted instances per model,
              including related models if cascading deletes were triggered.
    """
    return delete_provider(tenant_id=tenant_id, pk=provider_id)


@shared_task(base=RLSTask, name="scan-perform", queue="scans")
@handle_provider_deletion
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

    _perform_scan_complete_tasks(tenant_id, scan_id, provider_id)

    return result


@shared_task(base=RLSTask, bind=True, name="scan-perform-scheduled", queue="scans")
@handle_provider_deletion
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
        executing_scan = (
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state=StateChoices.EXECUTING,
            )
            .order_by("-started_at")
            .first()
        )
        if executing_scan:
            logger.warning(
                f"Scheduled scan already executing for provider {provider_id}. Skipping."
            )
            return ScanTaskSerializer(instance=executing_scan).data

        executed_scan = Scan.objects.filter(
            tenant_id=tenant_id,
            provider_id=provider_id,
            task__task_runner_task__task_id=task_id,
        ).first()

        if executed_scan:
            # Duplicated task execution due to visibility timeout
            logger.warning(f"Duplicated scheduled scan for provider {provider_id}.")
            return ScanTaskSerializer(instance=executed_scan).data

        interval = periodic_task_instance.interval
        next_scan_datetime = get_next_execution_datetime(task_id, provider_id)
        current_scan_datetime = next_scan_datetime - timedelta(
            **{interval.period: interval.every}
        )

        # TEMPORARY WORKAROUND: Clean up orphan scans from transaction isolation issue
        _cleanup_orphan_scheduled_scans(
            tenant_id=tenant_id,
            provider_id=provider_id,
            scheduler_task_id=periodic_task_instance.id,
        )

        scan_instance = _get_or_create_scheduled_scan(
            tenant_id=tenant_id,
            provider_id=provider_id,
            scheduler_task_id=periodic_task_instance.id,
            scheduled_at=current_scan_datetime,
        )
        scan_instance.task_id = task_id
        scan_instance.save()

    try:
        result = perform_prowler_scan(
            tenant_id=tenant_id,
            scan_id=str(scan_instance.id),
            provider_id=provider_id,
        )
    finally:
        with rls_transaction(tenant_id):
            now = datetime.now(timezone.utc)
            if next_scan_datetime <= now:
                interval_delta = timedelta(**{interval.period: interval.every})
                while next_scan_datetime <= now:
                    next_scan_datetime += interval_delta
            _get_or_create_scheduled_scan(
                tenant_id=tenant_id,
                provider_id=provider_id,
                scheduler_task_id=periodic_task_instance.id,
                scheduled_at=next_scan_datetime,
                update_state=True,
            )

    _perform_scan_complete_tasks(tenant_id, str(scan_instance.id), provider_id)

    return result


@shared_task(name="scan-summary", queue="overview")
@handle_provider_deletion
def perform_scan_summary_task(tenant_id: str, scan_id: str):
    return aggregate_findings(tenant_id=tenant_id, scan_id=scan_id)


class AttackPathsScanRLSTask(RLSTask):
    """
    RLS task that marks the `AttackPathsScan` DB row as `FAILED` when the Celery task fails.

    Covers failures that happen outside the job's own try/except (e.g. provider lookup,
    SDK initialization, or Neo4j configuration errors during setup).
    """

    def on_failure(self, exc, task_id, args, kwargs, _einfo):
        tenant_id = kwargs.get("tenant_id")
        scan_id = kwargs.get("scan_id")

        if tenant_id and scan_id:
            logger.error(f"Attack paths scan task {task_id} failed: {exc}")
            attack_paths_db_utils.fail_attack_paths_scan(tenant_id, scan_id, str(exc))


@shared_task(
    base=AttackPathsScanRLSTask,
    bind=True,
    name="attack-paths-scan-perform",
    queue="attack-paths-scans",
)
@handle_provider_deletion
def perform_attack_paths_scan_task(self, tenant_id: str, scan_id: str):
    """
    Execute an Attack Paths scan for the given provider within the current tenant RLS context.

    Args:
        self: The task instance (automatically passed when bind=True).
        tenant_id (str): The tenant identifier for RLS context.
        scan_id (str): The Prowler scan identifier for obtaining the tenant and provider context.

    Returns:
        Any: The result from `attack_paths_scan`, including any per-scan failure details.
    """
    return attack_paths_scan(
        tenant_id=tenant_id, scan_id=scan_id, task_id=self.request.id
    )


@shared_task(name="tenant-deletion", queue="deletion", autoretry_for=(Exception,))
def delete_tenant_task(tenant_id: str):
    return delete_tenant(pk=tenant_id)


@shared_task(
    base=RLSTask,
    name="scan-report",
    queue="scan-reports",
)
@set_tenant(keep_tenant=True)
@handle_provider_deletion
def generate_outputs_task(scan_id: str, provider_id: str, tenant_id: str):
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
    # Check if the scan has findings
    if not ScanSummary.objects.filter(scan_id=scan_id).exists():
        logger.info(f"No findings found for scan {scan_id}")
        return {"upload": False}

    provider_obj = Provider.objects.get(id=provider_id)
    prowler_provider = initialize_prowler_provider(provider_obj)
    provider_uid = provider_obj.uid
    provider_type = provider_obj.provider

    frameworks_bulk = Compliance.get_bulk(provider_type)
    frameworks_avail = get_compliance_frameworks(provider_type)
    out_dir, comp_dir = _generate_output_directory(
        DJANGO_TMP_OUTPUT_DIRECTORY, provider_uid, tenant_id, scan_id
    )

    def get_writer(writer_map, name, factory, is_last):
        """
        Return existing writer_map[name] or create via factory().
        In both cases set `.close_file = is_last`.
        """
        initialization = False
        if name not in writer_map:
            writer_map[name] = factory()
            initialization = True
        w = writer_map[name]
        w.close_file = is_last

        return w, initialization

    output_writers = {}
    compliance_writers = {}

    scan_summary = FindingOutput._transform_findings_stats(
        ScanSummary.objects.filter(scan_id=scan_id)
    )

    # Check if we need to generate ASFF output for AWS providers with SecurityHub integration
    generate_asff = False
    if provider_type == "aws":
        security_hub_integrations = Integration.objects.filter(
            integrationproviderrelationship__provider_id=provider_id,
            integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB,
            enabled=True,
        )
        generate_asff = security_hub_integrations.exists()

    qs = (
        Finding.all_objects.filter(tenant_id=tenant_id, scan_id=scan_id)
        .order_by("uid")
        .iterator()
    )
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        for batch, is_last in batched(qs, DJANGO_FINDINGS_BATCH_SIZE):
            fos = [
                FindingOutput.transform_api_finding(f, prowler_provider) for f in batch
            ]

            # Outputs
            for mode, cfg in OUTPUT_FORMATS_MAPPING.items():
                # Skip ASFF generation if not needed
                if mode == "json-asff" and not generate_asff:
                    continue

                cls = cfg["class"]
                suffix = cfg["suffix"]
                extra = cfg.get("kwargs", {}).copy()
                if mode == "html":
                    extra.update(provider=prowler_provider, stats=scan_summary)

                writer, initialization = get_writer(
                    output_writers,
                    cls,
                    lambda cls=cls, fos=fos, suffix=suffix: cls(
                        findings=fos,
                        file_path=out_dir,
                        file_extension=suffix,
                        from_cli=False,
                    ),
                    is_last,
                )
                if not initialization:
                    writer.transform(fos)
                writer.batch_write_data_to_file(**extra)
                writer._data.clear()

            # Compliance CSVs
            for name in frameworks_avail:
                compliance_obj = frameworks_bulk[name]

                klass = GenericCompliance
                for condition, cls in COMPLIANCE_CLASS_MAP.get(provider_type, []):
                    if condition(name):
                        klass = cls
                        break

                filename = f"{comp_dir}_{name}.csv"

                writer, initialization = get_writer(
                    compliance_writers,
                    name,
                    lambda klass=klass, fos=fos: klass(
                        findings=fos,
                        compliance=compliance_obj,
                        file_path=filename,
                        from_cli=False,
                    ),
                    is_last,
                )
                if not initialization:
                    writer.transform(fos, compliance_obj, name)
                writer.batch_write_data_to_file()
                writer._data.clear()

    compressed = _compress_output_files(out_dir)

    upload_uri = _upload_to_s3(
        tenant_id,
        scan_id,
        compressed,
        os.path.basename(compressed),
    )

    compliance_dir_path = Path(comp_dir).parent
    if compliance_dir_path.exists():
        for artifact_path in sorted(compliance_dir_path.iterdir()):
            if artifact_path.is_file():
                _upload_to_s3(
                    tenant_id,
                    scan_id,
                    str(artifact_path),
                    f"compliance/{artifact_path.name}",
                )

    # S3 integrations (need output_directory)
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        s3_integrations = Integration.objects.filter(
            integrationproviderrelationship__provider_id=provider_id,
            integration_type=Integration.IntegrationChoices.AMAZON_S3,
            enabled=True,
        )

    if s3_integrations:
        # Pass the output directory path to S3 integration task to reconstruct objects from files
        s3_integration_task.apply_async(
            kwargs={
                "tenant_id": tenant_id,
                "provider_id": provider_id,
                "output_directory": out_dir,
            }
        ).get(
            disable_sync_subtasks=False
        )  # TODO: This synchronous execution is NOT recommended
        # We're forced to do this because we need the files to exist before deletion occurs.
        # Once we have the periodic file cleanup task implemented, we should:
        # 1. Remove this .get() call and make it fully async
        # 2. For Cloud deployments, develop a secondary approach where outputs are stored
        #    directly in S3 and read from there, eliminating local file dependencies

    if upload_uri:
        # TODO: We need to create a new periodic task to delete the output files
        # This task shouldn't be responsible for deleting the output files
        try:
            rmtree(Path(compressed).parent, ignore_errors=True)
        except Exception as e:
            logger.error(f"Error deleting output files: {e}")
        final_location, did_upload = upload_uri, True
    else:
        final_location, did_upload = compressed, False

    Scan.all_objects.filter(id=scan_id).update(output_location=final_location)
    logger.info(f"Scan outputs at {final_location}")

    return {
        "upload": did_upload,
    }


@shared_task(name="backfill-scan-resource-summaries", queue="backfill")
@handle_provider_deletion
def backfill_scan_resource_summaries_task(tenant_id: str, scan_id: str):
    """
    Tries to backfill the resource scan summaries table for a given scan.

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
    """
    return backfill_resource_scan_summaries(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="backfill-compliance-summaries", queue="backfill")
@handle_provider_deletion
def backfill_compliance_summaries_task(tenant_id: str, scan_id: str):
    """
    Tries to backfill compliance overview summaries for a completed scan.

    This task aggregates compliance requirement data across regions
    to create pre-computed summary records for fast compliance overview queries.

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
    """
    return backfill_compliance_summaries(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="backfill-daily-severity-summaries", queue="backfill")
def backfill_daily_severity_summaries_task(tenant_id: str, days: int = None):
    """Backfill DailySeveritySummary from historical scans. Use days param to limit scope."""
    return backfill_daily_severity_summaries(tenant_id=tenant_id, days=days)


@shared_task(name="backfill-scan-category-summaries", queue="backfill")
@handle_provider_deletion
def backfill_scan_category_summaries_task(tenant_id: str, scan_id: str):
    """
    Backfill ScanCategorySummary for a completed scan.

    Aggregates unique categories from findings and creates a summary row.

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
    """
    return backfill_scan_category_summaries(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="backfill-scan-resource-group-summaries", queue="backfill")
@handle_provider_deletion
def backfill_scan_resource_group_summaries_task(tenant_id: str, scan_id: str):
    """
    Backfill ScanGroupSummary for a completed scan.

    Aggregates unique resource groups from findings and creates a summary row.

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
    """
    return backfill_scan_resource_group_summaries(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="backfill-provider-compliance-scores", queue="backfill")
def backfill_provider_compliance_scores_task(tenant_id: str):
    """
    Backfill ProviderComplianceScore from latest completed scan per provider.

    Used to populate the compliance watchlist materialized table for tenants
    that had scans before the feature was deployed.

    Args:
        tenant_id: Target tenant UUID.
    """
    return backfill_provider_compliance_scores(tenant_id=tenant_id)


@shared_task(base=RLSTask, name="scan-compliance-overviews", queue="compliance")
@handle_provider_deletion
def create_compliance_requirements_task(tenant_id: str, scan_id: str):
    """
    Creates detailed compliance requirement records for a scan.

    This task processes the compliance data collected during a scan and creates
    individual records for each compliance requirement in each region. These detailed
    records provide a granular view of compliance status.

    Args:
        tenant_id (str): The tenant ID for which to create records.
        scan_id (str): The ID of the scan for which to create records.
    """
    return create_compliance_requirements(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="scan-attack-surface-overviews", queue="overview")
@handle_provider_deletion
def aggregate_attack_surface_task(tenant_id: str, scan_id: str):
    """
    Creates attack surface overview records for a scan.

    This task processes findings and aggregates them into attack surface categories
    (internet-exposed, secrets, privilege-escalation, ec2-imdsv1) for quick overview queries.

    Args:
        tenant_id (str): The tenant ID for which to create records.
        scan_id (str): The ID of the scan for which to create records.
    """
    return aggregate_attack_surface(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="scan-provider-compliance-scores", queue="compliance")
def update_provider_compliance_scores_task(tenant_id: str, scan_id: str):
    """
    Update provider compliance scores from a completed scan.

    This task materializes compliance requirement statuses into ProviderComplianceScore
    for efficient watchlist queries. Uses atomic upsert with concurrency protection.

    Args:
        tenant_id (str): The tenant ID for which to update scores.
        scan_id (str): The ID of the scan whose data should be materialized.
    """
    return update_provider_compliance_scores(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(name="scan-daily-severity", queue="overview")
@handle_provider_deletion
def aggregate_daily_severity_task(tenant_id: str, scan_id: str):
    """Aggregate scan severity into DailySeveritySummary for findings_severity/timeseries endpoint."""
    return aggregate_daily_severity(tenant_id=tenant_id, scan_id=scan_id)


@shared_task(base=RLSTask, name="lighthouse-connection-check")
@set_tenant
def check_lighthouse_connection_task(lighthouse_config_id: str, tenant_id: str = None):
    """
    Task to check the connection status of a Lighthouse configuration.

    Args:
        lighthouse_config_id (str): The primary key of the LighthouseConfiguration instance to check.
        tenant_id (str): The tenant ID for the task.

    Returns:
        dict: A dictionary containing:
            - 'connected' (bool): Indicates whether the connection is successful.
            - 'error' (str or None): The error message if the connection failed, otherwise `None`.
            - 'available_models' (list): List of available models if connection is successful.
    """
    return check_lighthouse_connection(lighthouse_config_id=lighthouse_config_id)


@shared_task(base=RLSTask, name="lighthouse-provider-connection-check")
@set_tenant
def check_lighthouse_provider_connection_task(
    provider_config_id: str, tenant_id: str | None = None
) -> dict:
    """Task wrapper to validate provider credentials and set is_active."""
    return check_lighthouse_provider_connection(provider_config_id=provider_config_id)


@shared_task(base=RLSTask, name="lighthouse-provider-models-refresh")
@set_tenant
def refresh_lighthouse_provider_models_task(
    provider_config_id: str, tenant_id: str | None = None
) -> dict:
    """Task wrapper to refresh provider models catalog for the given configuration."""
    return refresh_lighthouse_provider_models(provider_config_id=provider_config_id)


@shared_task(name="integration-check")
@handle_provider_deletion
def check_integrations_task(tenant_id: str, provider_id: str, scan_id: str = None):
    """
    Check and execute all configured integrations for a provider.

    Args:
        tenant_id (str): The tenant identifier
        provider_id (str): The provider identifier
        scan_id (str, optional): The scan identifier for integrations that need scan data
    """
    logger.info(f"Checking integrations for provider {provider_id}")

    try:
        integration_tasks = []
        with rls_transaction(tenant_id):
            integrations = Integration.objects.filter(
                integrationproviderrelationship__provider_id=provider_id,
                enabled=True,
            )

            if not integrations.exists():
                logger.info(f"No integrations configured for provider {provider_id}")
                return {"integrations_processed": 0}

            # Security Hub integration
            security_hub_integrations = integrations.filter(
                integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB
            )
            if security_hub_integrations.exists():
                integration_tasks.append(
                    security_hub_integration_task.s(
                        tenant_id=tenant_id, provider_id=provider_id, scan_id=scan_id
                    )
                )

        # TODO: Add other integration types here
        # slack_integrations = integrations.filter(
        #     integration_type=Integration.IntegrationChoices.SLACK
        # )
        # if slack_integrations.exists():
        #     integration_tasks.append(
        #        slack_integration_task.s(
        #            tenant_id=tenant_id,
        #            provider_id=provider_id,
        #        )
        #     )

    except Exception as e:
        logger.error(f"Integration check failed for provider {provider_id}: {str(e)}")
        return {"integrations_processed": 0, "error": str(e)}

    # Execute all integration tasks in parallel if any were found
    if integration_tasks:
        job = group(integration_tasks)
        job.apply_async()
        logger.info(f"Launched {len(integration_tasks)} integration task(s)")

    return {"integrations_processed": len(integration_tasks)}


@shared_task(
    base=RLSTask,
    name="integration-s3",
    queue="integrations",
)
@handle_provider_deletion
def s3_integration_task(
    tenant_id: str,
    provider_id: str,
    output_directory: str,
):
    """
    Process S3 integrations for a provider.

    Args:
        tenant_id (str): The tenant identifier
        provider_id (str): The provider identifier
        output_directory (str): Path to the directory containing output files
    """
    return upload_s3_integration(tenant_id, provider_id, output_directory)


@shared_task(
    base=RLSTask,
    name="integration-security-hub",
    queue="integrations",
)
def security_hub_integration_task(
    tenant_id: str,
    provider_id: str,
    scan_id: str,
):
    """
    Process Security Hub integrations for a provider.

    Args:
        tenant_id (str): The tenant identifier
        provider_id (str): The provider identifier
        scan_id (str): The scan identifier
    """
    return upload_security_hub_integration(tenant_id, provider_id, scan_id)


@shared_task(
    base=RLSTask,
    name="integration-jira",
    queue="integrations",
)
def jira_integration_task(
    tenant_id: str,
    integration_id: str,
    project_key: str,
    issue_type: str,
    finding_ids: list[str],
):
    return send_findings_to_jira(
        tenant_id, integration_id, project_key, issue_type, finding_ids
    )


@shared_task(
    base=RLSTask,
    name="scan-compliance-reports",
    queue="scan-reports",
)
@handle_provider_deletion
def generate_compliance_reports_task(tenant_id: str, scan_id: str, provider_id: str):
    """
    Optimized task to generate ThreatScore, ENS, NIS2, and CSA CCM reports with shared queries.

    This task is more efficient than running separate report tasks because it reuses database queries:
    - Provider object fetched once (instead of multiple times)
    - Requirement statistics aggregated once (instead of multiple times)
    - Can reduce database load by up to 50-70%

    Args:
        tenant_id (str): The tenant identifier.
        scan_id (str): The scan identifier.
        provider_id (str): The provider identifier.

    Returns:
        dict: Results for all reports containing upload status and paths.
    """
    return generate_compliance_reports_job(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        generate_threatscore=True,
        generate_ens=True,
        generate_nis2=True,
        generate_csa=True,
    )


@shared_task(name="findings-mute-historical")
def mute_historical_findings_task(tenant_id: str, mute_rule_id: str):
    """
    Background task to mute all historical findings matching a mute rule.

    This task processes findings in batches to avoid memory issues with large datasets.
    It updates the Finding.muted, Finding.muted_at, and Finding.muted_reason fields
    for all findings whose UID is in the mute rule's finding_uids list.

    Args:
        tenant_id (str): The tenant ID for RLS context.
        mute_rule_id (str): The primary key of the MuteRule to apply.

    Returns:
        dict: A dictionary containing:
            - 'findings_muted' (int): Total number of findings muted.
            - 'rule_id' (str): The mute rule ID.
            - 'status' (str): Final status ('completed').
    """
    return mute_historical_findings(tenant_id, mute_rule_id)
