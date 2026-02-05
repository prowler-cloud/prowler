import csv
import io
import json
import re
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import sentry_sdk
from celery.utils.log import get_task_logger
from config.env import env
from config.settings.celery import CELERY_DEADLOCK_ATTEMPTS
from django.db import IntegrityError, OperationalError
from django.db.models import Case, Count, IntegerField, Max, Min, Prefetch, Q, Sum, When
from django.utils import timezone as django_timezone
from tasks.jobs.queries import (
    COMPLIANCE_UPSERT_PROVIDER_SCORE_SQL,
    COMPLIANCE_UPSERT_TENANT_SUMMARY_SQL,
)
from tasks.utils import CustomEncoder

from api.compliance import PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE
from api.constants import SEVERITY_ORDER
from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import (
    POSTGRES_TENANT_VAR,
    SET_CONFIG_QUERY,
    psycopg_connection,
    rls_transaction,
    update_objects_in_batches,
)
from api.exceptions import ProviderConnectionError
from api.models import (
    AttackSurfaceOverview,
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    FindingGroupDailySummary,
    MuteRule,
    Processor,
    Provider,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    ResourceTag,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    ScanSummary,
    StateChoices,
)
from api.models import StatusChoices as FindingStatus
from api.utils import initialize_prowler_provider, return_prowler_provider
from api.v1.serializers import ScanTaskSerializer
from prowler.lib.check.models import CheckMetadata
from prowler.lib.outputs.finding import Finding as ProwlerFinding
from prowler.lib.scan.scan import Scan as ProwlerScan

logger = get_task_logger(__name__)

# Column order must match `ComplianceRequirementOverview` schema in
# `api/models.py`. Keep this list minimal but sufficient to populate all
# non-nullable fields plus the counters we care about.
COMPLIANCE_REQUIREMENT_COPY_COLUMNS = (
    "id",
    "tenant_id",
    "inserted_at",
    "compliance_id",
    "framework",
    "version",
    "description",
    "region",
    "requirement_id",
    "requirement_status",
    "passed_checks",
    "failed_checks",
    "total_checks",
    "passed_findings",
    "total_findings",
    "scan_id",
)
# Controls how many findings we process per micro-batch before flushing to DB writes
FINDINGS_MICRO_BATCH_SIZE = env.int("DJANGO_FINDINGS_MICRO_BATCH_SIZE", default=3000)
# Controls how many rows each ORM bulk_create/bulk_update call sends to Postgres
SCAN_DB_BATCH_SIZE = env.int("DJANGO_SCAN_DB_BATCH_SIZE", default=500)

ATTACK_SURFACE_PROVIDER_COMPATIBILITY = {
    "internet-exposed": None,  # Compatible with all providers
    "secrets": None,  # Compatible with all providers
    "privilege-escalation": ["aws", "kubernetes"],
    "ec2-imdsv1": ["aws"],
}

_ATTACK_SURFACE_MAPPING_CACHE: dict[str, dict] = {}


def aggregate_category_counts(
    categories: list[str],
    severity: str,
    status: str,
    delta: str | None,
    muted: bool,
    cache: dict[tuple[str, str], dict[str, int]],
) -> None:
    """
    Increment category counters in-place for a finding.

    Args:
        categories: List of categories from finding metadata.
        severity: Severity level (e.g., "high", "medium").
        status: Finding status as string ("FAIL", "PASS").
        delta: Delta value as string ("new", "changed") or None.
        muted: Whether the finding is muted.
        cache: Dict {(category, severity): {"total", "failed", "new_failed"}} to update.
    """
    is_failed = status == "FAIL" and not muted
    is_new_failed = is_failed and delta == "new"

    for cat in categories:
        key = (cat, severity)
        if key not in cache:
            cache[key] = {"total": 0, "failed": 0, "new_failed": 0}
        if not muted:
            cache[key]["total"] += 1
        if is_failed:
            cache[key]["failed"] += 1
        if is_new_failed:
            cache[key]["new_failed"] += 1


def aggregate_resource_group_counts(
    resource_group: str | None,
    severity: str,
    status: str,
    delta: str | None,
    muted: bool,
    resource_uid: str,
    cache: dict[tuple[str, str], dict[str, int]],
    group_resources_cache: dict[str, set],
) -> None:
    """
    Increment resource group counters in-place for a finding.

    Args:
        resource_group: Resource group from check metadata (e.g., "database", "compute").
        severity: Severity level (e.g., "high", "medium").
        status: Finding status as string ("FAIL", "PASS").
        delta: Delta value as string ("new", "changed") or None.
        muted: Whether the finding is muted.
        resource_uid: Unique identifier for the resource to count distinct resources.
        cache: Dict {(resource_group, severity): {"total", "failed", "new_failed"}} to update.
        group_resources_cache: Dict {resource_group: set(resource_uids)} for group-level resource tracking.
    """
    if not resource_group:
        return

    is_failed = status == "FAIL" and not muted
    is_new_failed = is_failed and delta == "new"

    key = (resource_group, severity)
    if key not in cache:
        cache[key] = {"total": 0, "failed": 0, "new_failed": 0}
    if not muted:
        cache[key]["total"] += 1
    if is_failed:
        cache[key]["failed"] += 1
    if is_new_failed:
        cache[key]["new_failed"] += 1

    # Track resources at GROUP level (not per-severity) to avoid over-counting
    if resource_uid and not muted:
        group_resources_cache.setdefault(resource_group, set()).add(resource_uid)


def _get_attack_surface_mapping_from_provider(provider_type: str) -> dict:
    global _ATTACK_SURFACE_MAPPING_CACHE

    if provider_type in _ATTACK_SURFACE_MAPPING_CACHE:
        return _ATTACK_SURFACE_MAPPING_CACHE[provider_type]

    attack_surface_check_mappings = {
        "internet-exposed": None,
        "secrets": None,
        "privilege-escalation": {
            "iam_policy_allows_privilege_escalation",
            "iam_inline_policy_allows_privilege_escalation",
        },
        "ec2-imdsv1": {
            "ec2_instance_imdsv2_enabled"
        },  # AWS only - IMDSv1 enabled findings
    }
    for category_name, check_ids in attack_surface_check_mappings.items():
        if check_ids is None:
            sdk_check_ids = CheckMetadata.list(
                provider=provider_type, category=category_name
            )
            attack_surface_check_mappings[category_name] = sdk_check_ids

    _ATTACK_SURFACE_MAPPING_CACHE[provider_type] = attack_surface_check_mappings
    return attack_surface_check_mappings


def _create_finding_delta(
    last_status: FindingStatus | None | str, new_status: FindingStatus | None
) -> Finding.DeltaChoices:
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
    finding: ProwlerFinding, tenant_id: str, provider_instance: Provider
) -> tuple[Resource, tuple[str, str]]:
    """
    Store resource information from a finding, including tags, in the database.

    Args:
        finding (ProwlerFinding): The finding object containing resource information.
        tenant_id (str): The ID of the tenant owning the resource.
        provider_instance (Provider): The provider instance associated with the resource.

    Returns:
        tuple:
            - Resource: The resource instance created or retrieved from the database.
            - tuple[str, str]: A tuple containing the resource UID and region.

    """
    with rls_transaction(tenant_id):
        resource_instance, created = Resource.objects.get_or_create(
            tenant_id=tenant_id,
            provider=provider_instance,
            uid=finding.resource_uid,
            defaults={
                "region": finding.region,
                "service": finding.service_name,
                "type": finding.resource_type,
            },
        )

        if not created:
            resource_instance.region = finding.region
            resource_instance.service = finding.service_name
            resource_instance.type = finding.resource_type
            resource_instance.save()
    with rls_transaction(tenant_id):
        tags = [
            ResourceTag.objects.get_or_create(
                tenant_id=tenant_id, key=key, value=value
            )[0]
            for key, value in finding.resource_tags.items()
        ]
        resource_instance.upsert_or_delete_tags(tags=tags)
    return resource_instance, (resource_instance.uid, resource_instance.region)


def _copy_compliance_requirement_rows(
    tenant_id: str, rows: list[dict[str, Any]]
) -> None:
    """Stream compliance requirement rows into Postgres using COPY.

    We leverage the admin connection (when available) to bypass the COPY + RLS
    restriction, writing only the fields required by
    ``ComplianceRequirementOverview``.

    Args:
        tenant_id: Target tenant UUID.
        rows: List of row dictionaries prepared by
            :func:`create_compliance_requirements`.
    """

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)

    datetime_now = datetime.now(tz=timezone.utc)
    for row in rows:
        writer.writerow(
            [
                str(row.get("id")),
                str(row.get("tenant_id")),
                (row.get("inserted_at") or datetime_now).isoformat(),
                row.get("compliance_id") or "",
                row.get("framework") or "",
                row.get("version") or "",
                row.get("description") or "",
                row.get("region") or "",
                row.get("requirement_id") or "",
                row.get("requirement_status") or "",
                row.get("passed_checks", 0),
                row.get("failed_checks", 0),
                row.get("total_checks", 0),
                row.get("passed_findings", 0),
                row.get("total_findings", 0),
                str(row.get("scan_id")),
            ]
        )

    csv_buffer.seek(0)
    copy_sql = (
        "COPY compliance_requirements_overviews ("
        + ", ".join(COMPLIANCE_REQUIREMENT_COPY_COLUMNS)
        + ") FROM STDIN WITH (FORMAT CSV, DELIMITER ',', QUOTE '\"', ESCAPE '\"', NULL '\\N')"
    )

    try:
        with psycopg_connection(MainRouter.admin_db) as connection:
            connection.autocommit = False
            try:
                with connection.cursor() as cursor:
                    cursor.execute(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])
                    cursor.copy_expert(copy_sql, csv_buffer)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
    finally:
        csv_buffer.close()


def _persist_compliance_requirement_rows(
    tenant_id: str, rows: list[dict[str, Any]], batch_size: int = 10000
) -> None:
    """Persist compliance requirement rows using batched COPY with ORM fallback.

    Splits large row sets into batches to reduce lock duration and improve concurrency.

    Args:
        tenant_id: Target tenant UUID.
        rows: Precomputed row dictionaries that reflect the compliance
            overview state for a scan.
        batch_size: Number of rows per COPY batch (default: 10000).
    """
    if not rows:
        return

    total_rows = len(rows)
    total_batches = (total_rows + batch_size - 1) // batch_size

    try:
        # Process rows in batches to reduce lock duration
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, total_rows)
            batch = rows[start_idx:end_idx]

            _copy_compliance_requirement_rows(tenant_id, batch)

            logger.info(
                f"Compliance COPY batch {batch_num + 1}/{total_batches}: "
                f"inserted {len(batch)} rows ({start_idx + len(batch)}/{total_rows} total)"
            )
    except Exception as error:
        logger.exception(
            "COPY bulk insert for compliance requirements failed; falling back to ORM bulk_create",
            exc_info=error,
        )
        # Fallback: use ORM bulk_create for all remaining rows
        fallback_objects = [
            ComplianceRequirementOverview(
                id=row["id"],
                tenant_id=row["tenant_id"],
                inserted_at=row["inserted_at"],
                compliance_id=row["compliance_id"],
                framework=row["framework"],
                version=row["version"],
                description=row["description"],
                region=row["region"],
                requirement_id=row["requirement_id"],
                requirement_status=row["requirement_status"],
                passed_checks=row["passed_checks"],
                failed_checks=row["failed_checks"],
                total_checks=row["total_checks"],
                passed_findings=row.get("passed_findings", 0),
                total_findings=row.get("total_findings", 0),
                scan_id=row["scan_id"],
            )
            for row in rows
        ]
        with rls_transaction(tenant_id):
            ComplianceRequirementOverview.objects.bulk_create(
                fallback_objects, batch_size=500
            )


def _create_compliance_summaries(
    tenant_id: str, scan_id: str, requirement_statuses: dict
) -> None:
    """
    Create pre-aggregated compliance summaries from pre-computed requirement statuses.

    This computes the overall compliance scores across all regions for fast
    lookup in the main compliance overview endpoint.

    Args:
        tenant_id: Target tenant UUID
        scan_id: Scan UUID
        requirement_statuses: Pre-computed dict of {(compliance_id, requirement_id): {fail_count, pass_count, total_count}}
    """
    # Determine per-requirement status and aggregate to compliance level
    compliance_summaries = defaultdict(
        lambda: {
            "total_requirements": 0,
            "requirements_passed": 0,
            "requirements_failed": 0,
            "requirements_manual": 0,
        }
    )

    for (compliance_id, requirement_id), counts in requirement_statuses.items():
        # Apply business rule: any FAIL → requirement fails
        if counts["fail_count"] > 0:
            req_status = "FAIL"
        elif counts["pass_count"] == counts["total_count"]:
            req_status = "PASS"
        else:
            req_status = "MANUAL"

        # Aggregate to compliance level
        compliance_summaries[compliance_id]["total_requirements"] += 1
        if req_status == "PASS":
            compliance_summaries[compliance_id]["requirements_passed"] += 1
        elif req_status == "FAIL":
            compliance_summaries[compliance_id]["requirements_failed"] += 1
        else:
            compliance_summaries[compliance_id]["requirements_manual"] += 1

    # Create summary objects
    summary_objects = []
    for compliance_id, data in compliance_summaries.items():
        summary_objects.append(
            ComplianceOverviewSummary(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id,
                requirements_passed=data["requirements_passed"],
                requirements_failed=data["requirements_failed"],
                requirements_manual=data["requirements_manual"],
                total_requirements=data["total_requirements"],
            )
        )

    # Bulk insert summaries
    if summary_objects:
        with rls_transaction(tenant_id):
            ComplianceOverviewSummary.objects.bulk_create(
                summary_objects, batch_size=500, ignore_conflicts=True
            )


def _normalized_compliance_key(framework: str | None, version: str | None) -> str:
    """Return normalized identifier used to group compliance totals."""

    def _normalize(value: str | None) -> str:
        if not value:
            return ""
        return re.sub(r"[^a-z0-9]", "", value.lower())

    return f"{_normalize(framework)}{_normalize(version)}"


def _process_finding_micro_batch(
    tenant_id: str,
    findings_batch: list[ProwlerFinding],
    scan_instance: Scan,
    provider_instance: Provider,
    resource_cache: dict,
    tag_cache: dict,
    last_status_cache: dict,
    resource_failed_findings_cache: dict,
    unique_resources: set,
    scan_resource_cache: set,
    mute_rules_cache: dict,
    scan_categories_cache: dict[tuple[str, str], dict[str, int]],
    scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]],
    group_resources_cache: dict[str, set],
) -> None:
    """
    Process a micro-batch of findings and persist them using bulk operations.

    Each batch reuses caches (resources, tags, last statuses, mute rules) to avoid
    redundant queries, updates denormalized resource data, and writes findings plus
    resource mappings in as few transactions as possible.

    Args:
        tenant_id: Tenant owning the scan.
        findings_batch: Findings yielded by the Prowler scanner for this slice.
        scan_instance: Scan ORM instance being updated.
        provider_instance: Provider tied to the scan.
        resource_cache: In-memory cache of provider resources indexed by UID.
        tag_cache: Cache of `ResourceTag` instances keyed by (key, value).
        last_status_cache: Cache of prior finding statuses keyed by finding UID.
        resource_failed_findings_cache: Mutable counter of failed findings per resource.
        unique_resources: Set tracking (uid, region) pairs seen in the scan.
        scan_resource_cache: Set of tuples used to create `ResourceScanSummary` rows.
        mute_rules_cache: Map of finding UID -> mute reason gathered before the scan.
        scan_categories_cache: Dict tracking category counts {(category, severity): {"total", "failed", "new_failed"}}.
        scan_resource_groups_cache: Dict tracking resource group counts {(resource_group, severity): {"total", "failed", "new_failed"}}.
        group_resources_cache: Dict tracking unique resources per group {resource_group: set(resource_uids)}.
    """
    # Accumulate objects for bulk operations
    findings_to_create = []
    mappings_to_create = []
    dirty_resources = {}
    resource_denormalized_data = []  # (finding_instance, resource_instance) pairs
    skipped_findings_count = 0  # Track findings skipped due to UID length

    # Prefetch last statuses for all findings in this batch
    # TEMPORARY WORKAROUND: Filter out UIDs > 300 chars to avoid query errors
    finding_uids = [
        f.uid for f in findings_batch if f is not None and len(f.uid) <= 300
    ]
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        last_statuses = {
            item["uid"]: (item["status"], item["first_seen_at"])
            for item in Finding.all_objects.filter(
                tenant_id=tenant_id, uid__in=finding_uids
            )
            .values("uid", "status", "first_seen_at")
            .order_by("uid", "-inserted_at")
            .distinct("uid")
        }
        # Update cache
        for uid, data in last_statuses.items():
            if uid not in last_status_cache:
                last_status_cache[uid] = data

    # Process each finding in the batch
    for finding in findings_batch:
        if finding is None:
            logger.error(f"None finding detected on scan {scan_instance.id}.")
            continue

        # Process resource with deadlock retry
        for attempt in range(CELERY_DEADLOCK_ATTEMPTS):
            try:
                with rls_transaction(tenant_id):
                    resource_uid = finding.resource_uid
                    if resource_uid not in resource_cache:
                        check_metadata = finding.get_metadata()
                        group = check_metadata.get("resourcegroup") or None
                        resource_instance, _ = Resource.objects.get_or_create(
                            tenant_id=tenant_id,
                            provider=provider_instance,
                            uid=resource_uid,
                            defaults={
                                "region": finding.region,
                                "service": finding.service_name,
                                "type": finding.resource_type,
                                "name": finding.resource_name,
                                "groups": [group] if group else None,
                            },
                        )
                        resource_cache[resource_uid] = resource_instance
                        resource_failed_findings_cache[resource_uid] = 0
                    else:
                        resource_instance = resource_cache[resource_uid]
                break
            except (OperationalError, IntegrityError) as db_err:
                if attempt < CELERY_DEADLOCK_ATTEMPTS - 1:
                    logger.warning(
                        f"{'Deadlock error' if isinstance(db_err, OperationalError) else 'Integrity error'} "
                        f"detected when processing resource {resource_uid} on scan {scan_instance.id}. Retrying..."
                    )
                    time.sleep(0.1 * (2**attempt))
                    continue
                else:
                    raise db_err

        # Track resource field changes (defer save)
        updated = False
        check_metadata = finding.get_metadata()
        group = check_metadata.get("resourcegroup") or None
        if finding.region and resource_instance.region != finding.region:
            resource_instance.region = finding.region
            updated = True
        if resource_instance.service != finding.service_name:
            resource_instance.service = finding.service_name
            updated = True
        if resource_instance.type != finding.resource_type:
            resource_instance.type = finding.resource_type
            updated = True
        if resource_instance.metadata != finding.resource_metadata:
            resource_instance.metadata = json.dumps(
                finding.resource_metadata, cls=CustomEncoder
            )
            updated = True
        if resource_instance.details != finding.resource_details:
            resource_instance.details = finding.resource_details
            updated = True
        if resource_instance.partition != finding.partition:
            resource_instance.partition = finding.partition
            updated = True
        if group and (
            not resource_instance.groups or group not in resource_instance.groups
        ):
            resource_instance.groups = (resource_instance.groups or []) + [group]
            updated = True

        if updated:
            dirty_resources[resource_uid] = resource_instance

        # Process tags
        tags = []
        with rls_transaction(tenant_id):
            for key, value in finding.resource_tags.items():
                tag_key = (key, value)
                if tag_key not in tag_cache:
                    tag_instance, _ = ResourceTag.objects.get_or_create(
                        tenant_id=tenant_id, key=key, value=value
                    )
                    tag_cache[tag_key] = tag_instance
                else:
                    tag_instance = tag_cache[tag_key]
                tags.append(tag_instance)
            resource_instance.upsert_or_delete_tags(tags=tags)

        unique_resources.add((resource_instance.uid, resource_instance.region))

        # Prepare finding data
        finding_uid = finding.uid

        # TEMPORARY WORKAROUND: Skip findings with UID > 300 chars
        # TODO: Remove this after implementing text field migration for finding.uid
        if len(finding_uid) > 300:
            skipped_findings_count += 1
            logger.warning(
                f"Skipping finding with UID exceeding 300 characters. "
                f"Length: {len(finding_uid)}, "
                f"Check: {finding.check_id}, "
                f"Resource: {finding.resource_name}, "
                f"UID: {finding_uid}"
            )
            continue

        last_status, last_first_seen_at = last_status_cache.get(
            finding_uid, (None, None)
        )

        status = FindingStatus[finding.status]
        delta = _create_finding_delta(last_status, status)

        if not last_first_seen_at:
            last_first_seen_at = datetime.now(tz=timezone.utc)

        # Determine if finding should be muted and why
        # Priority: mutelist processor (highest) > manual mute rules
        is_muted = False
        muted_reason = None

        # Check mutelist processor first (highest priority)
        if finding.muted:
            is_muted = True
            muted_reason = "Muted by mutelist"
        # If not muted by mutelist, check manual mute rules
        elif finding_uid in mute_rules_cache:
            is_muted = True
            muted_reason = mute_rules_cache[finding_uid]

        # Increment failed_findings_count cache if needed
        if status == FindingStatus.FAIL and not is_muted:
            resource_failed_findings_cache[resource_uid] += 1

        # Create finding object (don't save yet)
        check_metadata = finding.get_metadata()
        finding_instance = Finding(
            tenant_id=tenant_id,
            uid=finding_uid,
            delta=delta,
            check_metadata=check_metadata,
            status=status,
            status_extended=finding.status_extended,
            severity=finding.severity,
            impact=finding.severity,
            raw_result=finding.raw,
            check_id=finding.check_id,
            scan=scan_instance,
            first_seen_at=last_first_seen_at,
            muted=is_muted,
            muted_at=datetime.now(tz=timezone.utc) if is_muted else None,
            muted_reason=muted_reason,
            compliance=finding.compliance,
            categories=check_metadata.get("categories", []) or [],
            resource_groups=check_metadata.get("resourcegroup") or None,
        )
        findings_to_create.append(finding_instance)
        resource_denormalized_data.append((finding_instance, resource_instance))

        # Track for scan summary
        scan_resource_cache.add(
            (
                str(resource_instance.id),
                resource_instance.service,
                resource_instance.region,
                resource_instance.type,
            )
        )

        # Track categories with counts for ScanCategorySummary by (category, severity)
        aggregate_category_counts(
            categories=check_metadata.get("categories", []) or [],
            severity=finding.severity.value,
            status=status.value,
            delta=delta.value if delta else None,
            muted=is_muted,
            cache=scan_categories_cache,
        )

        # Track resource groups with counts for ScanGroupSummary
        aggregate_resource_group_counts(
            resource_group=check_metadata.get("resourcegroup") or None,
            severity=finding.severity.value,
            status=status.value,
            delta=delta.value if delta else None,
            muted=is_muted,
            resource_uid=resource_instance.uid if resource_instance else "",
            cache=scan_resource_groups_cache,
            group_resources_cache=group_resources_cache,
        )

    # Bulk operations within single transaction
    with rls_transaction(tenant_id):
        # Bulk create findings
        if findings_to_create:
            Finding.objects.bulk_create(
                findings_to_create, batch_size=SCAN_DB_BATCH_SIZE
            )

        # Bulk create resource-finding mappings
        for finding_instance, resource_instance in resource_denormalized_data:
            mappings_to_create.append(
                ResourceFindingMapping(
                    tenant_id=tenant_id,
                    resource=resource_instance,
                    finding=finding_instance,
                )
            )

        if mappings_to_create:
            ResourceFindingMapping.objects.bulk_create(
                mappings_to_create,
                batch_size=SCAN_DB_BATCH_SIZE,
                ignore_conflicts=True,
            )

        # Update finding denormalized arrays
        findings_to_update = []
        for finding_instance, resource_instance in resource_denormalized_data:
            if not finding_instance.resource_regions:
                finding_instance.resource_regions = []
            if not finding_instance.resource_services:
                finding_instance.resource_services = []
            if not finding_instance.resource_types:
                finding_instance.resource_types = []

            if resource_instance.region not in finding_instance.resource_regions:
                finding_instance.resource_regions.append(resource_instance.region)
            if resource_instance.service not in finding_instance.resource_services:
                finding_instance.resource_services.append(resource_instance.service)
            if resource_instance.type not in finding_instance.resource_types:
                finding_instance.resource_types.append(resource_instance.type)

            findings_to_update.append(finding_instance)

        if findings_to_update:
            Finding.objects.bulk_update(
                findings_to_update,
                ["resource_regions", "resource_services", "resource_types"],
                batch_size=SCAN_DB_BATCH_SIZE,
            )

    # Bulk update dirty resources
    if dirty_resources:
        update_objects_in_batches(
            tenant_id=tenant_id,
            model=Resource,
            objects=list(dirty_resources.values()),
            fields=[
                "metadata",
                "details",
                "partition",
                "region",
                "service",
                "type",
                "groups",
            ],
            batch_size=1000,
        )

    # Log skipped findings summary
    if skipped_findings_count > 0:
        logger.warning(
            f"Scan {scan_instance.id}: Skipped {skipped_findings_count} finding(s) "
            f"due to UID length exceeding 300 characters in this micro-batch."
        )


def perform_prowler_scan(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    checks_to_execute: list[str] | None = None,
):
    """
    Run a Prowler scan and persist all generated resources, findings, and summaries.

    The scan stream is processed in micro-batches to keep memory bounded while still
    benefiting from bulk writes. When the scan completes we also derive
    `ResourceScanSummary` rows and return the serialized `Scan` payload used by the
    API layer.

    Args:
        tenant_id: Tenant that owns the scan.
        scan_id: UUID of the `Scan` row being executed.
        provider_id: Provider to authenticate against.
        checks_to_execute: Optional subset of check IDs to run.

    Returns:
        Serialized `ScanTaskSerializer` data for the updated scan.

    Raises:
        ProviderConnectionError: If the provider cannot be validated before scanning.
        Exception: Any downstream persistence/processing error (re-raised after cleanup).
    """
    exception = None
    unique_resources = set()
    scan_resource_cache: set[tuple[str, str, str, str]] = set()
    scan_categories_cache: dict[tuple[str, str], dict[str, int]] = {}
    scan_resource_groups_cache: dict[tuple[str, str], dict[str, int]] = {}
    group_resources_cache: dict[str, set] = {}
    start_time = time.time()
    exc = None

    with rls_transaction(tenant_id):
        provider_instance = Provider.objects.get(pk=provider_id)
        scan_instance = Scan.objects.get(pk=scan_id)
        scan_instance.state = StateChoices.EXECUTING
        scan_instance.started_at = datetime.now(tz=timezone.utc)
        scan_instance.save()

    # Find the mutelist processor if it exists
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        try:
            mutelist_processor = Processor.objects.get(
                tenant_id=tenant_id, processor_type=Processor.ProcessorChoices.MUTELIST
            )
        except Processor.DoesNotExist:
            mutelist_processor = None
        except Exception as e:
            logger.error(f"Error processing mutelist rules: {e}")
            mutelist_processor = None

    # Load enabled mute rules for this tenant
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        try:
            active_mute_rules = MuteRule.objects.filter(
                tenant_id=tenant_id, enabled=True
            ).values_list("finding_uids", "reason")

            mute_rules_cache = {}
            for finding_uids, reason in active_mute_rules:
                for uid in finding_uids:
                    mute_rules_cache[uid] = reason
        except Exception as e:
            logger.error(f"Error loading mute rules: {e}")
            mute_rules_cache = {}

    try:
        with rls_transaction(tenant_id):
            try:
                prowler_provider = initialize_prowler_provider(
                    provider_instance, mutelist_processor
                )
                provider_instance.connected = True
            except Exception as e:
                provider_instance.connected = False
                exc = ProviderConnectionError(
                    f"Provider {provider_instance.provider} is not connected: {e}"
                )
            finally:
                provider_instance.connection_last_checked_at = datetime.now(
                    tz=timezone.utc
                )
                provider_instance.save()

        # If the provider is not connected, raise an exception outside the transaction.
        # If raised within the transaction, the transaction will be rolled back and the provider will not be marked
        # as not connected.
        if exc:
            raise exc

        prowler_scan = ProwlerScan(provider=prowler_provider, checks=checks_to_execute)

        resource_cache = {}
        tag_cache = {}
        last_status_cache = {}
        resource_failed_findings_cache = defaultdict(int)

        for progress, findings in prowler_scan.scan():
            # Process findings in micro-batches
            findings_list = list(findings)
            total_findings = len(findings_list)

            # Chunk findings into micro-batches
            for i in range(0, total_findings, FINDINGS_MICRO_BATCH_SIZE):
                micro_batch = findings_list[i : i + FINDINGS_MICRO_BATCH_SIZE]

                _process_finding_micro_batch(
                    tenant_id=tenant_id,
                    findings_batch=micro_batch,
                    scan_instance=scan_instance,
                    provider_instance=provider_instance,
                    resource_cache=resource_cache,
                    tag_cache=tag_cache,
                    last_status_cache=last_status_cache,
                    resource_failed_findings_cache=resource_failed_findings_cache,
                    unique_resources=unique_resources,
                    scan_resource_cache=scan_resource_cache,
                    mute_rules_cache=mute_rules_cache,
                    scan_categories_cache=scan_categories_cache,
                    scan_resource_groups_cache=scan_resource_groups_cache,
                    group_resources_cache=group_resources_cache,
                )

            # Update scan progress
            with rls_transaction(tenant_id):
                scan_instance.progress = progress
                scan_instance.save()

        scan_instance.state = StateChoices.COMPLETED

        # Update failed_findings_count for all resources in batches if scan completed successfully
        if resource_failed_findings_cache:
            resources_to_update = []
            for resource_uid, failed_count in resource_failed_findings_cache.items():
                if resource_uid in resource_cache:
                    resource_instance = resource_cache[resource_uid]
                    resource_instance.failed_findings_count = failed_count
                    resources_to_update.append(resource_instance)

            if resources_to_update:
                update_objects_in_batches(
                    tenant_id=tenant_id,
                    model=Resource,
                    objects=resources_to_update,
                    fields=["failed_findings_count"],
                    batch_size=1000,
                )

    except Exception as e:
        logger.error(f"Error performing scan {scan_id}: {e}")
        exception = e
        scan_instance.state = StateChoices.FAILED

    finally:
        with rls_transaction(tenant_id):
            scan_instance.duration = time.time() - start_time
            scan_instance.completed_at = datetime.now(tz=timezone.utc)
            scan_instance.unique_resource_count = len(unique_resources)
            scan_instance.save()

    if exception is not None:
        raise exception

    try:
        resource_scan_summaries = [
            ResourceScanSummary(
                tenant_id=tenant_id,
                scan_id=scan_id,
                resource_id=resource_id,
                service=service,
                region=region,
                resource_type=resource_type,
            )
            for resource_id, service, region, resource_type in scan_resource_cache
        ]
        with rls_transaction(tenant_id):
            ResourceScanSummary.objects.bulk_create(
                resource_scan_summaries, batch_size=500, ignore_conflicts=True
            )
    except Exception as filter_exception:
        sentry_sdk.capture_exception(filter_exception)
        logger.error(
            f"Error storing filter values for scan {scan_id}: {filter_exception}"
        )

    try:
        if scan_categories_cache:
            category_summaries = [
                ScanCategorySummary(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    category=category,
                    severity=severity,
                    total_findings=counts["total"],
                    failed_findings=counts["failed"],
                    new_failed_findings=counts["new_failed"],
                )
                for (category, severity), counts in scan_categories_cache.items()
            ]
            with rls_transaction(tenant_id):
                ScanCategorySummary.objects.bulk_create(
                    category_summaries, batch_size=500, ignore_conflicts=True
                )
    except Exception as cat_exception:
        sentry_sdk.capture_exception(cat_exception)
        logger.error(f"Error storing categories for scan {scan_id}: {cat_exception}")

    try:
        if scan_resource_groups_cache:
            # Compute group-level resource counts (same value for all severity rows in a group)
            group_resource_counts = {
                grp: len(uids) for grp, uids in group_resources_cache.items()
            }
            resource_group_summaries = [
                ScanGroupSummary(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    resource_group=grp,
                    severity=severity,
                    total_findings=counts["total"],
                    failed_findings=counts["failed"],
                    new_failed_findings=counts["new_failed"],
                    resources_count=group_resource_counts.get(grp, 0),
                )
                for (
                    grp,
                    severity,
                ), counts in scan_resource_groups_cache.items()
            ]
            with rls_transaction(tenant_id):
                ScanGroupSummary.objects.bulk_create(
                    resource_group_summaries, batch_size=500, ignore_conflicts=True
                )
    except Exception as rg_exception:
        sentry_sdk.capture_exception(rg_exception)
        logger.error(
            f"Error storing resource groups for scan {scan_id}: {rg_exception}"
        )

    serializer = ScanTaskSerializer(instance=scan_instance)
    return serializer.data


def aggregate_findings(tenant_id: str, scan_id: str):
    """
    Aggregate findings for a scan and populate `ScanSummary` rows.

    We group findings by check/service/severity/region and compute pass/fail/muted
    totals plus delta counts (new/changed/unchanged). The summary dataset feeds the
    overview API and dashboards, so it is recomputed every time a scan finishes.

    Args:
        tenant_id: Tenant that owns the scan.
        scan_id: Scan UUID whose findings should be aggregated.
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        findings = Finding.objects.filter(tenant_id=tenant_id, scan_id=scan_id)

        aggregation = findings.values(
            "check_id",
            "resources__service",
            "severity",
            "resources__region",
        ).annotate(
            fail=Sum(
                Case(
                    When(status="FAIL", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            _pass=Sum(
                Case(
                    When(status="PASS", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            muted_count=Sum(
                Case(
                    When(muted=True, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            total=Count("id"),
            new=Sum(
                Case(
                    When(delta="new", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            changed=Sum(
                Case(
                    When(delta="changed", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            unchanged=Sum(
                Case(
                    When(delta__isnull=True, muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            fail_new=Sum(
                Case(
                    When(delta="new", status="FAIL", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            fail_changed=Sum(
                Case(
                    When(delta="changed", status="FAIL", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            pass_new=Sum(
                Case(
                    When(delta="new", status="PASS", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            pass_changed=Sum(
                Case(
                    When(delta="changed", status="PASS", muted=False, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            muted_new=Sum(
                Case(
                    When(delta="new", muted=True, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
            muted_changed=Sum(
                Case(
                    When(delta="changed", muted=True, then=1),
                    default=0,
                    output_field=IntegerField(),
                )
            ),
        )

    with rls_transaction(tenant_id):
        scan_aggregations = {
            ScanSummary(
                tenant_id=tenant_id,
                scan_id=scan_id,
                check_id=agg["check_id"],
                service=agg["resources__service"],
                severity=agg["severity"],
                region=agg["resources__region"],
                fail=agg["fail"],
                _pass=agg["_pass"],
                muted=agg["muted_count"],
                total=agg["total"],
                new=agg["new"],
                changed=agg["changed"],
                unchanged=agg["unchanged"],
                fail_new=agg["fail_new"],
                fail_changed=agg["fail_changed"],
                pass_new=agg["pass_new"],
                pass_changed=agg["pass_changed"],
                muted_new=agg["muted_new"],
                muted_changed=agg["muted_changed"],
            )
            for agg in aggregation
        }
        ScanSummary.objects.bulk_create(scan_aggregations, batch_size=3000)


def _aggregate_findings_by_region(
    tenant_id: str, scan_id: str, modeled_threatscore_compliance_id: str
) -> tuple[dict, dict]:
    """
    Aggregate findings by region using optimized ORM queries.

    Replaces nested Python loops with efficient queries and aggregation.

    Args:
        tenant_id: Tenant UUID
        scan_id: Scan UUID
        modeled_threatscore_compliance_id: ID for ThreatScore compliance framework

    Returns:
        tuple: (check_status_by_region, findings_count_by_compliance)
            - check_status_by_region: {region: {check_id: status}}
            - findings_count_by_compliance: {region: {normalized_id: {requirement_id: {total, pass}}}}
    """
    check_status_by_region = {}
    findings_count_by_compliance = {}

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        # Fetch only PASS/FAIL findings (optimized query reduces data transfer)
        # Other statuses are not needed for check_status or ThreatScore calculation
        findings = (
            Finding.all_objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
                muted=False,
                status__in=["PASS", "FAIL"],
            )
            .only("id", "check_id", "status", "compliance")
            .prefetch_related(
                Prefetch(
                    "resources",
                    queryset=Resource.objects.only("id", "region"),
                    to_attr="small_resources",
                )
            )
        )

        # Process findings in a single pass (more efficient than original nested loops)
        normalized_id = re.sub(
            r"[^a-z0-9]", "", modeled_threatscore_compliance_id.lower()
        )

        for finding in findings:
            status = finding.status

            for resource in finding.small_resources:
                region = resource.region

                # Aggregate check status by region
                current_status = check_status_by_region.setdefault(region, {})
                # Priority: FAIL > any other status
                if current_status.get(finding.check_id) != "FAIL":
                    current_status[finding.check_id] = status

                # Aggregate ThreatScore compliance counts
                if modeled_threatscore_compliance_id in (finding.compliance or {}):
                    compliance_key = findings_count_by_compliance.setdefault(
                        region, {}
                    ).setdefault(normalized_id, {})

                    for requirement_id in finding.compliance[
                        modeled_threatscore_compliance_id
                    ]:
                        requirement_stats = compliance_key.setdefault(
                            requirement_id, {"total": 0, "pass": 0}
                        )
                        requirement_stats["total"] += 1
                        if status == "PASS":
                            requirement_stats["pass"] += 1

    return check_status_by_region, findings_count_by_compliance


def create_compliance_requirements(tenant_id: str, scan_id: str):
    """
    Materialize per-requirement compliance rows (and summaries) for a scan.

    Using the provider’s compliance template plus the scan’s findings, we compute a
    row per (region, compliance, requirement) and write it to
    `ComplianceRequirementOverview` via COPY. The same pass tally requirement
    statuses so we can persist `ComplianceOverviewSummary` records for the fast
    overview endpoint.

    Args:
        tenant_id: Tenant running the scan.
        scan_id: Scan identifier whose findings should be translated into compliance data.

    Returns:
        dict: Counts/metadata about the generated rows (e.g., frameworks touched, regions processed).
    """
    try:
        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
            scan_instance = Scan.objects.get(pk=scan_id)
            provider_instance = scan_instance.provider
            return_prowler_provider(provider_instance)

        compliance_template = PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE[
            provider_instance.provider
        ]
        modeled_threatscore_compliance_id = "ProwlerThreatScore-1.0"

        requirement_lookup: dict[str, list[tuple[str, str]]] = {}
        for compliance_id, compliance in compliance_template.items():
            for requirement_id, requirement in compliance["requirements"].items():
                for check_id in requirement["checks"].keys():
                    requirement_lookup.setdefault(check_id, []).append(
                        (compliance_id, requirement_id)
                    )

        compliance_requirement_rows: list[dict[str, Any]] = []
        regions = []
        requirement_statuses = defaultdict(
            lambda: {"fail_count": 0, "pass_count": 0, "total_count": 0}
        )

        # Skip if provider has no compliance frameworks
        if compliance_template:
            # Aggregate findings by region using SQL for optimal performance
            check_status_by_region, findings_count_by_compliance = (
                _aggregate_findings_by_region(
                    tenant_id, scan_id, modeled_threatscore_compliance_id
                )
            )

            # Only process regions that have findings (optimization: reduces row count)
            regions = list(check_status_by_region.keys())

            region_requirement_stats: dict[
                str, dict[str, dict[str, dict[str, int]]]
            ] = defaultdict(lambda: defaultdict(dict))
            for region, check_status in check_status_by_region.items():
                for check_name, status in check_status.items():
                    targets = requirement_lookup.get(check_name)
                    if not targets:
                        continue
                    status_lower = (status or "").lower()
                    if status_lower not in {"pass", "fail"}:
                        continue
                    for compliance_id, requirement_id in targets:
                        compliance_stats = region_requirement_stats[region].setdefault(
                            compliance_id, {}
                        )
                        requirement_stats = compliance_stats.setdefault(
                            requirement_id, {"passed_checks": 0, "failed_checks": 0}
                        )
                        if status_lower == "pass":
                            requirement_stats["passed_checks"] += 1
                        else:
                            requirement_stats["failed_checks"] += 1

            # Prepare compliance requirement rows and compute summaries in single pass
            utc_datetime_now = datetime.now(tz=timezone.utc)

            # Pre-compute shared strings (optimization: reduces string conversions)
            tenant_id_str = str(tenant_id)
            scan_id_str = str(scan_instance.id)

            for region in regions:
                region_stats = region_requirement_stats.get(region, {})
                for compliance_id, compliance in compliance_template.items():
                    modeled_compliance_id = _normalized_compliance_key(
                        compliance["framework"], compliance["version"]
                    )
                    compliance_stats = region_stats.get(compliance_id, {})
                    # Create an overview record for each requirement within each compliance framework
                    for requirement_id, requirement in compliance[
                        "requirements"
                    ].items():
                        stats = compliance_stats.get(requirement_id)
                        passed_checks = stats["passed_checks"] if stats else 0
                        failed_checks = stats["failed_checks"] if stats else 0
                        total_checks = len(requirement["checks"])
                        if total_checks == 0:
                            requirement_status = "MANUAL"
                        elif failed_checks > 0:
                            requirement_status = "FAIL"
                        else:
                            requirement_status = "PASS"

                        compliance_requirement_rows.append(
                            {
                                "id": uuid.uuid4(),
                                "tenant_id": tenant_id_str,
                                "inserted_at": utc_datetime_now,
                                "compliance_id": compliance_id,
                                "framework": compliance["framework"],
                                "version": compliance["version"] or "",
                                "description": requirement.get("description") or "",
                                "region": region,
                                "requirement_id": requirement_id,
                                "requirement_status": requirement_status,
                                "passed_checks": passed_checks,
                                "failed_checks": failed_checks,
                                "total_checks": total_checks,
                                "scan_id": scan_id_str,
                                "passed_findings": findings_count_by_compliance.get(
                                    region, {}
                                )
                                .get(modeled_compliance_id, {})
                                .get(requirement_id, {})
                                .get("pass", 0),
                                "total_findings": findings_count_by_compliance.get(
                                    region, {}
                                )
                                .get(modeled_compliance_id, {})
                                .get(requirement_id, {})
                                .get("total", 0),
                            }
                        )

                        # Update summary tracking (single-pass optimization)
                        key = (compliance_id, requirement_id)
                        requirement_statuses[key]["total_count"] += 1
                        if requirement_status == "FAIL":
                            requirement_statuses[key]["fail_count"] += 1
                        elif requirement_status == "PASS":
                            requirement_statuses[key]["pass_count"] += 1

            # Bulk create requirement records using PostgreSQL COPY
            _persist_compliance_requirement_rows(tenant_id, compliance_requirement_rows)

        # Create pre-aggregated summaries for fast compliance overview lookups
        _create_compliance_summaries(tenant_id, scan_id, requirement_statuses)

        return {
            "requirements_created": len(compliance_requirement_rows),
            "regions_processed": list(regions),
            "compliance_frameworks": (
                list(compliance_template.keys()) if regions else []
            ),
        }

    except Exception as e:
        logger.error(f"Error creating compliance requirements for scan {scan_id}: {e}")
        raise e


def aggregate_attack_surface(tenant_id: str, scan_id: str):
    """
    Aggregate findings into attack surface overview records.

    Creates one AttackSurfaceOverview record per attack surface type
    for the given scan, based on check_id mappings.

    Args:
        tenant_id: Tenant that owns the scan.
        scan_id: Scan UUID whose findings should be aggregated.
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        scan_instance = Scan.all_objects.select_related("provider").get(pk=scan_id)
        provider_type = scan_instance.provider.provider

    provider_attack_surface_mapping = _get_attack_surface_mapping_from_provider(
        provider_type=provider_type
    )

    # Filter out attack surfaces that are not compatible or have no resolved check IDs
    supported_mappings: dict[str, list[str]] = {}
    for attack_surface_type, check_ids in provider_attack_surface_mapping.items():
        compatible_providers = ATTACK_SURFACE_PROVIDER_COMPATIBILITY.get(
            attack_surface_type
        )
        if (
            compatible_providers is not None
            and provider_type not in compatible_providers
        ):
            logger.info(
                f"Skipping {attack_surface_type} - not supported for {provider_type}"
            )
            continue

        if not check_ids:
            logger.info(
                f"Skipping {attack_surface_type} - no check IDs resolved for {provider_type}"
            )
            continue

        supported_mappings[attack_surface_type] = list(check_ids)

    if not supported_mappings:
        logger.info(
            f"No attack surface mappings available for scan {scan_id} and provider {provider_type}"
        )
        logger.info(f"No attack surface overview records created for scan {scan_id}")
        return

    # Map every check_id to its attack surface, so we can aggregate with a single query
    check_id_to_surface: dict[str, str] = {}
    for attack_surface_type, check_ids in supported_mappings.items():
        for check_id in check_ids:
            check_id_to_surface[check_id] = attack_surface_type

    aggregated_counts = {
        attack_surface_type: {"total": 0, "failed": 0, "muted": 0}
        for attack_surface_type in supported_mappings.keys()
    }

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        finding_stats = (
            Finding.all_objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
                check_id__in=list(check_id_to_surface.keys()),
            )
            .values("check_id")
            .annotate(
                total=Count("id"),
                failed=Count("id", filter=Q(status="FAIL", muted=False)),
                muted=Count("id", filter=Q(status="FAIL", muted=True)),
            )
        )

        for stats in finding_stats:
            attack_surface_type = check_id_to_surface.get(stats["check_id"])
            if not attack_surface_type:
                continue

            aggregated_counts[attack_surface_type]["total"] += stats["total"] or 0
            aggregated_counts[attack_surface_type]["failed"] += stats["failed"] or 0
            aggregated_counts[attack_surface_type]["muted"] += stats["muted"] or 0

    overview_objects = []
    for attack_surface_type, counts in aggregated_counts.items():
        total = counts["total"]
        if not total:
            continue

        overview_objects.append(
            AttackSurfaceOverview(
                tenant_id=tenant_id,
                scan_id=scan_id,
                attack_surface_type=attack_surface_type,
                total_findings=total,
                failed_findings=counts["failed"],
                muted_failed_findings=counts["muted"],
            )
        )

    # Bulk create overview records
    if overview_objects:
        with rls_transaction(tenant_id):
            AttackSurfaceOverview.objects.bulk_create(overview_objects, batch_size=500)
            logger.info(
                f"Created {len(overview_objects)} attack surface overview records for scan {scan_id}"
            )
    else:
        logger.info(f"No attack surface overview records created for scan {scan_id}")


def aggregate_daily_severity(tenant_id: str, scan_id: str):
    """Aggregate scan severity counts into DailySeveritySummary (one record per provider/day)."""
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        scan = Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state=StateChoices.COMPLETED,
        ).first()

        if not scan:
            logger.warning(f"Scan {scan_id} not found or not completed")
            return {"status": "scan is not completed"}

        provider_id = scan.provider_id
        scan_date = scan.completed_at.date()

        severity_totals = (
            ScanSummary.objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            .values("severity")
            .annotate(total_fail=Sum("fail"), total_muted=Sum("muted"))
        )

        severity_data = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "muted": 0,
        }

        for row in severity_totals:
            severity = row["severity"]
            if severity in severity_data:
                severity_data[severity] = row["total_fail"] or 0
            severity_data["muted"] += row["total_muted"] or 0

    with rls_transaction(tenant_id):
        summary, created = DailySeveritySummary.objects.update_or_create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            date=scan_date,
            defaults={
                "scan_id": scan_id,
                "critical": severity_data["critical"],
                "high": severity_data["high"],
                "medium": severity_data["medium"],
                "low": severity_data["low"],
                "informational": severity_data["informational"],
                "muted": severity_data["muted"],
            },
        )

    action = "created" if created else "updated"
    logger.info(
        f"Daily severity summary {action} for provider {provider_id} on {scan_date}"
    )

    return {
        "status": action,
        "provider_id": str(provider_id),
        "date": str(scan_date),
        "severity_data": severity_data,
    }


def update_provider_compliance_scores(tenant_id: str, scan_id: str):
    """
    Update ProviderComplianceScore with requirement statuses from a completed scan.

    Uses atomic SQL upsert with ON CONFLICT for concurrency safety. Only updates
    if the new scan is more recent than existing data. Also cleans up stale
    requirements that no longer exist in the new scan.

    Reads from primary DB (not replica) to avoid replication lag issues since
    this runs immediately after create_compliance_requirements_task.

    Args:
        tenant_id: Tenant that owns the scan.
        scan_id: Scan UUID whose compliance data should be materialized.

    Returns:
        dict: Statistics about the upsert operation.
    """
    with rls_transaction(tenant_id):
        scan = (
            Scan.all_objects.filter(
                tenant_id=tenant_id,
                id=scan_id,
                state=StateChoices.COMPLETED,
            )
            .select_related("provider")
            .first()
        )

        if not scan:
            logger.warning(
                f"Scan {scan_id} not found or not completed for compliance score update"
            )
            return {"status": "skipped", "reason": "scan not completed"}

        if not scan.completed_at:
            logger.warning(f"Scan {scan_id} has no completed_at timestamp")
            return {"status": "skipped", "reason": "no completed_at"}

        provider_id = str(scan.provider_id)
        scan_completed_at = scan.completed_at

    delete_stale_sql = """
        DELETE FROM provider_compliance_scores pcs
        WHERE pcs.tenant_id = %s
          AND pcs.provider_id = %s
          AND pcs.scan_completed_at < %s
          AND NOT EXISTS (
              SELECT 1 FROM compliance_requirements_overviews cro
              WHERE cro.tenant_id = pcs.tenant_id
                AND cro.scan_id = %s
                AND cro.compliance_id = pcs.compliance_id
                AND cro.requirement_id = pcs.requirement_id
          )
        RETURNING compliance_id
    """

    compliance_ids_sql = """
        SELECT DISTINCT compliance_id
        FROM compliance_requirements_overviews
        WHERE tenant_id = %s AND scan_id = %s
    """

    try:
        with psycopg_connection(MainRouter.default_db) as connection:
            connection.autocommit = False
            try:
                with connection.cursor() as cursor:
                    cursor.execute(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])

                    # Update requirement-level scores per provider
                    cursor.execute(
                        COMPLIANCE_UPSERT_PROVIDER_SCORE_SQL, [tenant_id, scan_id]
                    )
                    upserted_count = cursor.rowcount

                    cursor.execute(compliance_ids_sql, [tenant_id, scan_id])
                    scan_rows = cursor.fetchall()
                    if not isinstance(scan_rows, (list, tuple)):
                        scan_rows = []
                    scan_compliance_ids = {row[0] for row in scan_rows}

                    cursor.execute(
                        delete_stale_sql,
                        [tenant_id, provider_id, scan_completed_at, scan_id],
                    )
                    deleted_rows = cursor.fetchall()
                    if not isinstance(deleted_rows, (list, tuple)):
                        deleted_rows = []
                    deleted_ids = {row[0] for row in deleted_rows}
                    stale_deleted = len(deleted_ids)

                    impacted_compliance_ids = sorted(scan_compliance_ids | deleted_ids)

                    if impacted_compliance_ids:
                        # Advisory lock on tenant to prevent race conditions when
                        # multiple scans complete simultaneously for the same tenant
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(hashtext(%s))", [tenant_id]
                        )

                        # Recalculate tenant-level summary (FAIL-dominant across all providers)
                        cursor.execute(
                            COMPLIANCE_UPSERT_TENANT_SUMMARY_SQL,
                            [tenant_id, tenant_id, impacted_compliance_ids],
                        )
                        tenant_summary_count = cursor.rowcount
                    else:
                        tenant_summary_count = 0

                connection.commit()
            except Exception:
                connection.rollback()
                raise

        logger.info(
            f"Provider compliance scores updated for scan {scan_id}: "
            f"{upserted_count} upserted, {stale_deleted} stale deleted, "
            f"{tenant_summary_count} tenant summaries upserted"
        )

        return {
            "status": "completed",
            "scan_id": str(scan_id),
            "provider_id": provider_id,
            "upserted": upserted_count,
            "stale_deleted": stale_deleted,
            "tenant_summary_count": tenant_summary_count,
        }

    except Exception as e:
        logger.error(
            f"Error updating provider compliance scores for scan {scan_id}: {e}"
        )
        raise


def aggregate_finding_group_summaries(tenant_id: str, scan_id: str):
    """
    Aggregate finding group summaries for a completed scan.

    Creates or updates FindingGroupDailySummary records for each unique check_id
    found in the scan's findings. These pre-aggregated summaries enable efficient
    queries over date ranges without scanning millions of findings.

    Args:
        tenant_id: Tenant that owns the scan.
        scan_id: Scan UUID whose findings should be aggregated.

    Returns:
        dict: Statistics about the aggregation operation.
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        scan = Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state=StateChoices.COMPLETED,
        ).first()

        if not scan:
            logger.warning(
                f"Scan {scan_id} not found or not completed for finding group summary"
            )
            return {"status": "skipped", "reason": "scan not completed"}

        if not scan.provider:
            logger.warning(f"Scan {scan_id} has no provider for finding group summary")
            return {"status": "skipped", "reason": "scan has no provider"}

        summary_timestamp = scan.completed_at
        if django_timezone.is_naive(summary_timestamp):
            summary_timestamp = django_timezone.make_aware(
                summary_timestamp, timezone.utc
            )
        summary_timestamp = summary_timestamp.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        provider_id = scan.provider_id

        # Build severity Case/When expression
        severity_case = Case(
            *[
                When(severity=severity, then=order)
                for severity, order in SEVERITY_ORDER.items()
            ],
            output_field=IntegerField(),
        )

        # Aggregate findings by check_id for this scan
        aggregated = (
            Finding.objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            .values("check_id")
            .annotate(
                severity_order=Max(severity_case),
                pass_count=Count("id", filter=Q(status="PASS", muted=False)),
                fail_count=Count("id", filter=Q(status="FAIL", muted=False)),
                muted_count=Count("id", filter=Q(muted=True)),
                new_count=Count("id", filter=Q(delta="new", muted=False)),
                changed_count=Count("id", filter=Q(delta="changed", muted=False)),
                resources_total=Count("resources__id", distinct=True),
                resources_fail=Count(
                    "resources__id",
                    distinct=True,
                    filter=Q(status="FAIL", muted=False),
                ),
                # Use prefixed names to avoid conflict with model field names
                agg_first_seen_at=Min("first_seen_at"),
                agg_last_seen_at=Max("inserted_at"),
                agg_failing_since=Min(
                    "first_seen_at", filter=Q(status="FAIL", muted=False)
                ),
            )
        )

        # Force evaluate queryset while inside RLS transaction (prevents lazy re-query issues)
        aggregated_list = list(aggregated)

        # Fetch check metadata for all check_ids in one query
        check_ids = [row["check_id"] for row in aggregated_list]
        check_metadata_map = {}
        if check_ids:
            findings_with_metadata = (
                Finding.objects.filter(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    check_id__in=check_ids,
                )
                .order_by("check_id")
                .distinct("check_id")
                .values("check_id", "check_metadata")
            )

            for f in findings_with_metadata:
                if f["check_id"] not in check_metadata_map and f["check_metadata"]:
                    check_metadata_map[f["check_id"]] = f["check_metadata"]

    # Upsert summaries in bulk for performance
    created_count = 0
    updated_count = 0

    with rls_transaction(tenant_id):
        check_ids = [row["check_id"] for row in aggregated_list]
        existing_check_ids = set()
        if check_ids:
            existing_check_ids = set(
                FindingGroupDailySummary.objects.filter(
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                    check_id__in=check_ids,
                    inserted_at=summary_timestamp,
                ).values_list("check_id", flat=True)
            )

        created_count = len(check_ids) - len(existing_check_ids)
        updated_count = len(existing_check_ids)

        summaries_to_upsert = []
        updated_at = django_timezone.now()
        for row in aggregated_list:
            check_id = row["check_id"]
            metadata = check_metadata_map.get(check_id, {})

            summaries_to_upsert.append(
                FindingGroupDailySummary(
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                    check_id=check_id,
                    inserted_at=summary_timestamp,
                    updated_at=updated_at,
                    check_title=metadata.get("checktitle", ""),
                    check_description=metadata.get("Description", ""),
                    severity_order=row["severity_order"] or 1,
                    pass_count=row["pass_count"],
                    fail_count=row["fail_count"],
                    muted_count=row["muted_count"],
                    new_count=row["new_count"],
                    changed_count=row["changed_count"],
                    resources_total=row["resources_total"],
                    resources_fail=row["resources_fail"],
                    first_seen_at=row["agg_first_seen_at"],
                    last_seen_at=row["agg_last_seen_at"],
                    failing_since=row["agg_failing_since"],
                )
            )

        if summaries_to_upsert:
            FindingGroupDailySummary.objects.bulk_create(
                summaries_to_upsert,
                update_conflicts=True,
                unique_fields=["tenant_id", "provider", "check_id", "inserted_at"],
                update_fields=[
                    "check_title",
                    "check_description",
                    "severity_order",
                    "pass_count",
                    "fail_count",
                    "muted_count",
                    "new_count",
                    "changed_count",
                    "resources_total",
                    "resources_fail",
                    "first_seen_at",
                    "last_seen_at",
                    "failing_since",
                    "updated_at",
                ],
            )

    logger.info(
        f"Finding group summaries aggregated for scan {scan_id}: "
        f"{created_count} created, {updated_count} updated"
    )

    return {
        "status": "completed",
        "scan_id": str(scan_id),
        "date": str(summary_timestamp.date()),
        "created": created_count,
        "updated": updated_count,
    }
