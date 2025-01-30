import os
import time
import zipfile
from copy import deepcopy
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from celery.utils.log import get_task_logger
from config.env import env
from config.settings.celery import CELERY_DEADLOCK_ATTEMPTS
from django.db import IntegrityError, OperationalError
from django.db.models import Case, Count, IntegerField, Sum, When

from api.compliance import (
    PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE,
    generate_scan_compliance,
)
from api.db_utils import rls_transaction
from api.models import (
    ComplianceOverview,
    Finding,
    Provider,
    Resource,
    ResourceTag,
    Scan,
    ScanSummary,
    StateChoices,
)
from api.models import StatusChoices as FindingStatus
from api.utils import initialize_prowler_provider
from api.v1.serializers import ScanTaskSerializer
from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_ocsf_file_suffix,
    output_file_timestamp,
    tmp_output_directory,
)
from prowler.lib.outputs.asff.asff import ASFF
from prowler.lib.outputs.csv.csv import CSV
from prowler.lib.outputs.finding import Finding as ProwlerFinding
from prowler.lib.outputs.html.html import HTML
from prowler.lib.outputs.ocsf.ocsf import OCSF
from prowler.lib.scan.scan import Scan as ProwlerScan

logger = get_task_logger(__name__)

# Predefined mapping for output formats and their configurations
OUTPUT_FORMATS_MAPPING = {
    "csv": {
        "class": CSV,
        "suffix": csv_file_suffix,
        "kwargs": {},
    },
    "json-asff": {"class": ASFF, "suffix": json_asff_file_suffix, "kwargs": {}},
    "json-ocsf": {"class": OCSF, "suffix": json_ocsf_file_suffix, "kwargs": {}},
    "html": {"class": HTML, "suffix": html_file_suffix, "kwargs": {"stats": {}}},
}

# Mapping provider types to their identity components for output paths
PROVIDER_IDENTITY_MAP = {
    "aws": lambda p: p.identity.account,
    "azure": lambda p: p.identity.tenant_domain,
    "gcp": lambda p: p.identity.profile,
    "kubernetes": lambda p: p.identity.context.replace(":", "_").replace("/", "_"),
}


def _compress_output_files(output_directory: str) -> str:
    """
    Compress output files from all configured output formats into a ZIP archive.

    Args:
        output_directory (str): The directory where the output files are located.
            The function looks up all known suffixes in OUTPUT_FORMATS_MAPPING
            and compresses those files into a single ZIP.

    Returns:
        str: The full path to the newly created ZIP archive.
    """
    zip_path = f"{output_directory}.zip"

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for suffix in [config["suffix"] for config in OUTPUT_FORMATS_MAPPING.values()]:
            zipf.write(
                f"{output_directory}{suffix}",
                f"artifacts/{output_directory.split('/')[-1]}{suffix}",
            )

    return zip_path


def _upload_to_s3(tenant_id: str, zip_path: str, scan_id: str) -> str:
    """
    Upload the specified ZIP file to an S3 bucket.

    If the S3 bucket environment variables are not configured,
    the function returns None without performing an upload.

    Args:
        tenant_id (str): The tenant identifier, used as part of the S3 key prefix.
        zip_path (str): The local file system path to the ZIP file to be uploaded.
        scan_id (str): The scan identifier, used as part of the S3 key prefix.

    Returns:
        str: The S3 URI of the uploaded file (e.g., "s3://<bucket>/<key>") if successful.
        None: If the required environment variables for the S3 bucket are not set.

    Raises:
        botocore.exceptions.ClientError: If the upload attempt to S3 fails for any reason.
    """
    if not env.str("ARTIFACTS_AWS_S3_OUTPUT_BUCKET", ""):
        return

    if env.str("ARTIFACTS_AWS_ACCESS_KEY_ID", ""):
        s3 = boto3.client(
            "s3",
            aws_access_key_id=env.str("ARTIFACTS_AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=env.str("ARTIFACTS_AWS_SECRET_ACCESS_KEY"),
            aws_session_token=env.str("ARTIFACTS_AWS_SESSION_TOKEN"),
            region_name=env.str("ARTIFACTS_AWS_DEFAULT_REGION"),
        )
    else:
        s3 = boto3.client("s3")

    s3_key = f"{tenant_id}/{scan_id}/{os.path.basename(zip_path)}"
    try:
        s3.upload_file(
            Filename=zip_path,
            Bucket=env.str("ARTIFACTS_AWS_S3_OUTPUT_BUCKET"),
            Key=s3_key,
        )
        return f"s3://{env.str("ARTIFACTS_AWS_S3_OUTPUT_BUCKET")}/{s3_key}"
    except ClientError as e:
        logger.error(f"S3 upload failed: {str(e)}")
        raise e


def _create_finding_delta(
    last_status: FindingStatus | None | str, new_status: FindingStatus | None
) -> Finding.DeltaChoices | None:
    """
    Determine the delta status of a finding based on its previous and current status.

    Args:
        last_status (FindingStatus | None | str): The previous status of the finding. Can be None or a string representation.
        new_status (FindingStatus | None): The current status of the finding.

    Returns:
        Finding.DeltaChoices: The delta status indicating if the finding is new, changed, or unchanged.
            - Returns `Finding.DeltaChoices.NEW` if `last_status` is None.
            - Returns `Finding.DeltaChoices.CHANGED` if `last_status` and `new_status` are different.
            - Returns `None` if the status hasn't changed.
    """
    if last_status is None:
        return Finding.DeltaChoices.NEW
    return Finding.DeltaChoices.CHANGED if last_status != new_status else None


def _store_resources(
    finding: ProwlerFinding,
    tenant_id: str,
    provider_instance: Provider,
    resource_cache: dict,
    tag_cache: dict,
) -> tuple[Resource, tuple[str, str]]:
    """
    Store resource information from a finding, including tags, in the database.

    Args:
        finding (ProwlerFinding): The finding object containing resource information.
        tenant_id (str): The ID of the tenant owning the resource.
        provider_instance (Provider): The provider instance associated with the resource.

    Returns:
        tuple:
            - Resource: The resource instance created or updated from the database.
            - tuple[str, str]: A tuple containing the resource UID and region.

    """
    resource_uid = finding.resource_uid

    # Check cache or create/update resource
    if resource_uid in resource_cache:
        resource_instance = resource_cache[resource_uid]
        update_fields = []
        for field, value in [
            ("region", finding.region),
            ("service", finding.service_name),
            ("type", finding.resource_type),
            ("name", finding.resource_name),
        ]:
            if getattr(resource_instance, field) != value:
                setattr(resource_instance, field, value)
                update_fields.append(field)
        if update_fields:
            with rls_transaction(tenant_id):
                resource_instance.save(update_fields=update_fields)
    else:
        with rls_transaction(tenant_id):
            resource_instance, _ = Resource.objects.update_or_create(
                tenant_id=tenant_id,
                provider=provider_instance,
                uid=resource_uid,
                defaults={
                    "region": finding.region,
                    "service": finding.service_name,
                    "type": finding.resource_type,
                    "name": finding.resource_name,
                },
            )
        resource_cache[resource_uid] = resource_instance

    # Process tags with caching
    tags = []
    for key, value in finding.resource_tags.items():
        tag_key = (key, value)
        if tag_key not in tag_cache:
            with rls_transaction(tenant_id):
                tag_instance, _ = ResourceTag.objects.get_or_create(
                    tenant_id=tenant_id, key=key, value=value
                )
                tag_cache[tag_key] = tag_instance
        tags.append(tag_cache[tag_key])

    with rls_transaction(tenant_id):
        resource_instance.upsert_or_delete_tags(tags=tags)

    return resource_instance, (resource_instance.uid, resource_instance.region)


def _generate_output_directory(
    prowler_provider: object, tenant_id: str, scan_id: str
) -> str:
    """
    Generate a dynamic output directory path based on the given provider type.

    Args:
        prowler_provider (object): An object that has a `type` attribute indicating
            the provider type (e.g., "aws", "azure", etc.).
        tenant_id (str): A unique identifier for the tenant. Used to build the output path.
        scan_id (str): A unique identifier for the scan. Included in the output path.

    Returns:
        str: The complete path to the output directory, including the tenant ID, scan ID,
            provider identity, and a timestamp.

    """
    provider_type = prowler_provider.type
    get_identity = PROVIDER_IDENTITY_MAP.get(provider_type, lambda _: "unknown")
    return (
        f"{tmp_output_directory}/{tenant_id}/{scan_id}/prowler-output-"
        f"{get_identity(prowler_provider)}-{output_file_timestamp}"
    )


def perform_prowler_scan(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    checks_to_execute: list[str] = None,
):
    """
    Perform a scan using Prowler and store the findings and resources in the database.

    Args:
        tenant_id (str): The ID of the tenant for which the scan is performed.
        scan_id (str): The ID of the scan instance.
        provider_id (str): The ID of the provider to scan.
        checks_to_execute (list[str], optional): A list of specific checks to execute. Defaults to None.

    Returns:
        dict: Serialized data of the completed scan instance.

    Raises:
        ValueError: If the provider cannot be connected.

    """
    check_status_by_region = {}
    exception = None
    unique_resources = set()
    start_time = time.time()
    resource_cache = {}
    tag_cache = {}
    last_status_cache = {}

    with rls_transaction(tenant_id):
        provider_instance = Provider.objects.get(pk=provider_id)
        scan_instance = Scan.objects.get(pk=scan_id)
        scan_instance.state = StateChoices.EXECUTING
        scan_instance.started_at = datetime.now(tz=timezone.utc)
        scan_instance.save()

    try:
        # Provider initialization
        with rls_transaction(tenant_id):
            try:
                prowler_provider = initialize_prowler_provider(provider_instance)
                provider_instance.connected = True
            except Exception as e:
                provider_instance.connected = False
                raise ValueError(
                    f"Provider {provider_instance.provider} is not connected: {e}"
                )
            finally:
                provider_instance.connection_last_checked_at = datetime.now(
                    tz=timezone.utc
                )
                provider_instance.save()

        # Scan configuration
        prowler_scan = ProwlerScan(
            provider=prowler_provider, checks=checks_to_execute or []
        )
        output_directory = _generate_output_directory(
            prowler_provider, tenant_id, scan_id
        )
        os.makedirs("/".join(output_directory.split("/")[:-1]), exist_ok=True)

        all_findings = []

        # Main scan loop
        for progress, findings, stats in prowler_scan.scan():
            # Process findings
            for finding in findings:
                # Resource processing with retries
                for attempt in range(CELERY_DEADLOCK_ATTEMPTS):
                    try:
                        resource_instance, resource_uid_region = _store_resources(
                            finding,
                            tenant_id,
                            provider_instance,
                            resource_cache,
                            tag_cache,
                        )
                        unique_resources.add(resource_uid_region)
                        break
                    except (OperationalError, IntegrityError) as db_err:
                        if attempt < CELERY_DEADLOCK_ATTEMPTS - 1:
                            logger.warning(
                                f"Database error ({type(db_err).__name__}) "
                                f"processing resource {finding.resource_uid}, retrying..."
                            )
                            time.sleep(0.1 * (2**attempt))
                        else:
                            raise db_err

                # Finding processing
                with rls_transaction(tenant_id):
                    finding_uid = finding.uid
                    if finding_uid not in last_status_cache:
                        most_recent = (
                            Finding.objects.filter(uid=finding_uid)
                            .order_by("-id")
                            .values("status", "first_seen_at")
                            .first()
                        )
                        last_status, first_seen = (
                            (most_recent["status"], most_recent["first_seen_at"])
                            if most_recent
                            else (None, None)
                        )
                        last_status_cache[finding_uid] = (last_status, first_seen)
                    else:
                        last_status, first_seen = last_status_cache[finding_uid]

                    status = FindingStatus[finding.status]
                    delta = _create_finding_delta(last_status, status)
                    first_seen = first_seen or datetime.now(tz=timezone.utc)

                    finding_instance = Finding.objects.create(
                        tenant_id=tenant_id,
                        uid=finding_uid,
                        delta=delta,
                        check_metadata=finding.get_metadata(),
                        status=status,
                        status_extended=finding.status_extended,
                        severity=finding.severity,
                        impact=finding.severity,
                        raw_result=finding.raw,
                        check_id=finding.check_id,
                        scan=scan_instance,
                        first_seen_at=first_seen,
                    )
                    finding_instance.add_resources([resource_instance])

                # Update compliance status
                if finding.status.value != "MUTED":
                    region_data = check_status_by_region.setdefault(finding.region, {})
                    if region_data.get(finding.check_id) != "FAIL":
                        region_data[finding.check_id] = finding.status.value

            # Progress updates and output generation
            with rls_transaction(tenant_id):
                scan_instance.progress = progress
                scan_instance.save()

            all_findings.extend(findings)

        # Generate output files
        for mode, config in OUTPUT_FORMATS_MAPPING.items():
            kwargs = dict(config["kwargs"])
            if mode == "html":
                kwargs["provider"] = prowler_provider
                kwargs["stats"] = stats
            config["class"](
                findings=all_findings,
                create_file_descriptor=True,
                file_path=output_directory,
                file_extension=config["suffix"],
            ).batch_write_data_to_file(**kwargs)

        scan_instance.state = StateChoices.COMPLETED

        # Compress output files
        zip_path = _compress_output_files(output_directory)

        # Save to configured storage
        _upload_to_s3(tenant_id, zip_path, scan_id)

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        exception = e
        scan_instance.state = StateChoices.FAILED

    finally:
        # Final scan updates
        with rls_transaction(tenant_id):
            scan_instance.duration = time.time() - start_time
            scan_instance.completed_at = datetime.now(tz=timezone.utc)
            scan_instance.unique_resource_count = len(unique_resources)
            scan_instance.save()

    # Compliance processing
    if not exception:
        compliance_template = PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE[
            provider_instance.provider
        ]
        compliance_overview = {
            region: deepcopy(compliance_template)
            for region in getattr(prowler_provider, "get_regions", lambda: set())()
        }

        for region, checks in check_status_by_region.items():
            for check_id, status in checks.items():
                generate_scan_compliance(
                    compliance_overview.setdefault(
                        region, deepcopy(compliance_template)
                    ),
                    provider_instance.provider,
                    check_id,
                    status,
                )

        ComplianceOverview.objects.bulk_create(
            [
                ComplianceOverview(
                    tenant_id=tenant_id,
                    scan=scan_instance,
                    region=region,
                    compliance_id=compliance_id,
                    **compliance_data,
                )
                for region, data in compliance_overview.items()
                for compliance_id, compliance_data in data.items()
            ]
        )

    if exception:
        raise exception

    return ScanTaskSerializer(instance=scan_instance).data


def aggregate_findings(tenant_id: str, scan_id: str):
    """
    Aggregates findings for a given scan and stores the results in the ScanSummary table.

    This function retrieves all findings associated with a given `scan_id` and calculates various
    metrics such as counts of failed, passed, and muted findings, as well as their deltas (new,
    changed, unchanged). The results are grouped by `check_id`, `service`, `severity`, and `region`.
    These aggregated metrics are then stored in the `ScanSummary` table.

    Args:
        tenant_id (str): The ID of the tenant to which the scan belongs.
        scan_id (str): The ID of the scan for which findings need to be aggregated.

    Aggregated Metrics:
        - fail: Total number of failed findings.
        - _pass: Total number of passed findings.
        - muted: Total number of muted findings.
        - total: Total number of findings.
        - new: Total number of new findings.
        - changed: Total number of changed findings.
        - unchanged: Total number of unchanged findings.
        - fail_new: Failed findings with a delta of 'new'.
        - fail_changed: Failed findings with a delta of 'changed'.
        - pass_new: Passed findings with a delta of 'new'.
        - pass_changed: Passed findings with a delta of 'changed'.
        - muted_new: Muted findings with a delta of 'new'.
        - muted_changed: Muted findings with a delta of 'changed'.
    """
    with rls_transaction(tenant_id):
        aggregation = (
            Finding.objects.filter(scan_id=scan_id)
            .values(
                "check_id",
                "resources__service",
                "severity",
                "resources__region",
            )
            .annotate(
                fail=Sum(
                    Case(
                        When(status="FAIL", then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                _pass=Sum(
                    Case(
                        When(status="PASS", then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                muted=Sum(
                    Case(
                        When(status="MUTED", then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                total=Count("id"),
                new=Sum(
                    Case(
                        When(delta="new", then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                changed=Sum(
                    Case(
                        When(delta="changed", then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                unchanged=Sum(
                    Case(
                        When(delta__isnull=True, then=1),
                        default=0,
                        output_field=IntegerField(),
                    )
                ),
                **{
                    f"{status}_new": Sum(
                        Case(
                            When(delta="new", status=status.upper(), then=1),
                            default=0,
                            output_field=IntegerField(),
                        )
                    )
                    for status in ["fail", "pass", "muted"]
                },
                **{
                    f"{status}_changed": Sum(
                        Case(
                            When(delta="changed", status=status.upper(), then=1),
                            default=0,
                            output_field=IntegerField(),
                        )
                    )
                    for status in ["fail", "pass", "muted"]
                },
            )
        )

        ScanSummary.objects.bulk_create(
            [
                ScanSummary(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    check_id=agg["check_id"],
                    service=agg["resources__service"],
                    severity=agg["severity"],
                    region=agg["resources__region"],
                    **{
                        k: v or 0
                        for k, v in agg.items()
                        if k
                        not in {
                            "check_id",
                            "resources__service",
                            "severity",
                            "resources__region",
                        }
                    },
                )
                for agg in aggregation
            ],
            batch_size=3000,
        )
