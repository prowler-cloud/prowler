from collections import defaultdict
from datetime import timedelta

from celery.utils.log import get_task_logger
from django.db.models import OuterRef, Subquery, Sum
from django.utils import timezone
from tasks.jobs.queries import (
    COMPLIANCE_UPSERT_PROVIDER_SCORE_SQL,
    COMPLIANCE_UPSERT_TENANT_SUMMARY_ALL_SQL,
)
from tasks.jobs.scan import (
    aggregate_category_counts,
    aggregate_finding_group_summaries,
    aggregate_resource_group_counts,
)

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import (
    POSTGRES_TENANT_VAR,
    SET_CONFIG_QUERY,
    psycopg_connection,
    rls_transaction,
)
from api.models import (
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    ProviderComplianceScore,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    ScanSummary,
    StateChoices,
)

logger = get_task_logger(__name__)


def backfill_resource_scan_summaries(tenant_id: str, scan_id: str):
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if ResourceScanSummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).exists():
            return {"status": "already backfilled"}

    with rls_transaction(tenant_id):
        if not Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state__in=(StateChoices.COMPLETED, StateChoices.FAILED),
        ).exists():
            return {"status": "scan is not completed"}

        resource_ids_qs = (
            ResourceFindingMapping.objects.filter(
                tenant_id=tenant_id, finding__scan_id=scan_id
            )
            .values_list("resource_id", flat=True)
            .distinct()
        )

        resource_ids = list(resource_ids_qs)

        if not resource_ids:
            return {"status": "no resources to backfill"}

        resources_qs = Resource.objects.filter(
            tenant_id=tenant_id, id__in=resource_ids
        ).only("id", "service", "region", "type")

        summaries = []
        for resource in resources_qs.iterator():
            summaries.append(
                ResourceScanSummary(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    resource_id=str(resource.id),
                    service=resource.service,
                    region=resource.region,
                    resource_type=resource.type,
                )
            )

        for i in range(0, len(summaries), 500):
            ResourceScanSummary.objects.bulk_create(
                summaries[i : i + 500], ignore_conflicts=True
            )

    return {"status": "backfilled", "inserted": len(summaries)}


def backfill_compliance_summaries(tenant_id: str, scan_id: str):
    """
    Backfill ComplianceOverviewSummary records for a completed scan.

    This function checks if summary records already exist for the scan.
    If not, it aggregates compliance requirement data and creates the summaries.

    Args:
        tenant_id: Target tenant UUID
        scan_id: Scan UUID to backfill

    Returns:
        dict: Status indicating whether backfill was performed
    """
    with rls_transaction(tenant_id):
        if ComplianceOverviewSummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).exists():
            return {"status": "already backfilled"}

    with rls_transaction(tenant_id):
        if not Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state__in=(StateChoices.COMPLETED, StateChoices.FAILED),
        ).exists():
            return {"status": "scan is not completed"}

        # Fetch all compliance requirement overview rows for this scan
        requirement_rows = ComplianceRequirementOverview.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).values(
            "compliance_id",
            "requirement_id",
            "requirement_status",
        )

        if not requirement_rows:
            return {"status": "no compliance data to backfill"}

        # Group by (compliance_id, requirement_id) across regions
        requirement_statuses = defaultdict(
            lambda: {"fail_count": 0, "pass_count": 0, "total_count": 0}
        )

        for row in requirement_rows:
            compliance_id = row["compliance_id"]
            requirement_id = row["requirement_id"]
            requirement_status = row["requirement_status"]

            # Aggregate requirement status across regions
            key = (compliance_id, requirement_id)
            requirement_statuses[key]["total_count"] += 1

            if requirement_status == "FAIL":
                requirement_statuses[key]["fail_count"] += 1
            elif requirement_status == "PASS":
                requirement_statuses[key]["pass_count"] += 1

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
            ComplianceOverviewSummary.objects.bulk_create(
                summary_objects, batch_size=500, ignore_conflicts=True
            )

    return {"status": "backfilled", "inserted": len(summary_objects)}


def backfill_daily_severity_summaries(tenant_id: str, days: int = None):
    """
    Backfill DailySeveritySummary from completed scans.
    Groups by provider+date, keeps latest scan per day.
    """
    created_count = 0
    updated_count = 0

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        scan_filter = {
            "tenant_id": tenant_id,
            "state": StateChoices.COMPLETED,
            "completed_at__isnull": False,
        }

        if days is not None:
            cutoff_date = timezone.now() - timedelta(days=days)
            scan_filter["completed_at__gte"] = cutoff_date

        completed_scans = (
            Scan.objects.filter(**scan_filter)
            .order_by("provider_id", "-completed_at")
            .values("id", "provider_id", "completed_at")
        )

        if not completed_scans:
            return {"status": "no scans to backfill"}

        # Keep only latest scan per provider/day
        latest_scans_by_day = {}
        for scan in completed_scans:
            key = (scan["provider_id"], scan["completed_at"].date())
            if key not in latest_scans_by_day:
                latest_scans_by_day[key] = scan

    # Process each provider/day
    for (provider_id, scan_date), scan in latest_scans_by_day.items():
        scan_id = scan["id"]

        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
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
            _, created = DailySeveritySummary.objects.update_or_create(
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

            if created:
                created_count += 1
            else:
                updated_count += 1

    return {
        "status": "backfilled",
        "created": created_count,
        "updated": updated_count,
        "total_days": len(latest_scans_by_day),
    }


def backfill_scan_category_summaries(tenant_id: str, scan_id: str):
    """
    Backfill ScanCategorySummary for a completed scan.

    Aggregates category counts from all findings in the scan and creates
    one ScanCategorySummary row per (category, severity) combination.

    Args:
        tenant_id: Target tenant UUID
        scan_id: Scan UUID to backfill

    Returns:
        dict: Status indicating whether backfill was performed
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if ScanCategorySummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).exists():
            return {"status": "already backfilled"}

        if not Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state__in=(StateChoices.COMPLETED, StateChoices.FAILED),
        ).exists():
            return {"status": "scan is not completed"}

        category_counts: dict[tuple[str, str], dict[str, int]] = {}
        for finding in Finding.all_objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).values("categories", "severity", "status", "delta", "muted"):
            aggregate_category_counts(
                categories=finding.get("categories") or [],
                severity=finding.get("severity"),
                status=finding.get("status"),
                delta=finding.get("delta"),
                muted=finding.get("muted", False),
                cache=category_counts,
            )

        if not category_counts:
            return {"status": "no categories to backfill"}

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
        for (category, severity), counts in category_counts.items()
    ]

    with rls_transaction(tenant_id):
        ScanCategorySummary.objects.bulk_create(
            category_summaries, batch_size=500, ignore_conflicts=True
        )

    return {"status": "backfilled", "categories_count": len(category_counts)}


def backfill_scan_resource_group_summaries(tenant_id: str, scan_id: str):
    """
    Backfill ScanGroupSummary for a completed scan.

    Aggregates resource group counts from all findings in the scan and creates
    one ScanGroupSummary row per (resource_group, severity) combination.

    Args:
        tenant_id: Target tenant UUID
        scan_id: Scan UUID to backfill

    Returns:
        dict: Status indicating whether backfill was performed
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if ScanGroupSummary.objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).exists():
            return {"status": "already backfilled"}

        if not Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state__in=(StateChoices.COMPLETED, StateChoices.FAILED),
        ).exists():
            return {"status": "scan is not completed"}

        resource_group_counts: dict[tuple[str, str], dict[str, int]] = {}
        group_resources_cache: dict[str, set] = {}
        # Get findings with their first resource UID via annotation
        resource_uid_subquery = ResourceFindingMapping.objects.filter(
            finding_id=OuterRef("id"), tenant_id=tenant_id
        ).values("resource__uid")[:1]

        for finding in (
            Finding.all_objects.filter(tenant_id=tenant_id, scan_id=scan_id)
            .annotate(resource_uid=Subquery(resource_uid_subquery))
            .values(
                "resource_groups",
                "severity",
                "status",
                "delta",
                "muted",
                "resource_uid",
            )
        ):
            aggregate_resource_group_counts(
                resource_group=finding.get("resource_groups"),
                severity=finding.get("severity"),
                status=finding.get("status"),
                delta=finding.get("delta"),
                muted=finding.get("muted", False),
                resource_uid=finding.get("resource_uid") or "",
                cache=resource_group_counts,
                group_resources_cache=group_resources_cache,
            )

        if not resource_group_counts:
            return {"status": "no resource groups to backfill"}

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
        for (grp, severity), counts in resource_group_counts.items()
    ]

    with rls_transaction(tenant_id):
        ScanGroupSummary.objects.bulk_create(
            resource_group_summaries, batch_size=500, ignore_conflicts=True
        )

    return {"status": "backfilled", "resource_groups_count": len(resource_group_counts)}


def backfill_provider_compliance_scores(tenant_id: str) -> dict:
    """
    Backfill ProviderComplianceScore from latest completed scan per provider.

    For each provider with completed scans, finds the most recent scan and
    upserts compliance requirement statuses with FAIL-dominant aggregation.

    Args:
        tenant_id: Target tenant UUID

    Returns:
        dict: Statistics about the backfill operation
    """
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        completed_scans = Scan.all_objects.filter(
            tenant_id=tenant_id,
            state=StateChoices.COMPLETED,
            completed_at__isnull=False,
        )
        if not completed_scans.exists():
            return {"status": "no completed scans"}

        existing_providers = set(
            ProviderComplianceScore.objects.filter(tenant_id=tenant_id)
            .values_list("provider_id", flat=True)
            .distinct()
        )

        if existing_providers:
            completed_scans = completed_scans.exclude(
                provider_id__in=existing_providers
            )

        scan_info = list(
            completed_scans.order_by("provider_id", "-completed_at")
            .distinct("provider_id")
            .values("id", "provider_id", "completed_at")
        )

        if not scan_info:
            return {"status": "no scans to process"}

    total_upserted = 0
    providers_processed = 0
    providers_skipped = 0

    for scan in scan_info:
        provider_id = scan["provider_id"]

        scan_id = scan["id"]

        try:
            with psycopg_connection(MainRouter.default_db) as connection:
                connection.autocommit = False
                try:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id]
                        )
                        cursor.execute(
                            COMPLIANCE_UPSERT_PROVIDER_SCORE_SQL,
                            [tenant_id, str(scan_id)],
                        )
                        upserted = cursor.rowcount
                    connection.commit()
                    total_upserted += upserted
                    providers_processed += 1
                except Exception:
                    connection.rollback()
                    raise
        except Exception as e:
            providers_skipped += 1
            logger.exception(
                "Error backfilling provider %s for tenant %s: %s",
                provider_id,
                tenant_id,
                e,
            )

    # Recalculate tenant summary after all providers are backfilled
    if providers_processed > 0:
        with psycopg_connection(MainRouter.default_db) as connection:
            connection.autocommit = False
            try:
                with connection.cursor() as cursor:
                    cursor.execute(SET_CONFIG_QUERY, [POSTGRES_TENANT_VAR, tenant_id])
                    # Advisory lock to prevent race conditions
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))", [tenant_id]
                    )
                    cursor.execute(
                        COMPLIANCE_UPSERT_TENANT_SUMMARY_ALL_SQL,
                        [tenant_id, tenant_id],
                    )
                    tenant_summary_count = cursor.rowcount
                connection.commit()
            except Exception:
                connection.rollback()
                raise
    else:
        tenant_summary_count = 0

    return {
        "status": "backfilled",
        "providers_processed": providers_processed,
        "providers_skipped": providers_skipped,
        "total_upserted": total_upserted,
        "tenant_summary_count": tenant_summary_count,
    }


def backfill_finding_group_summaries(tenant_id: str, days: int = None):
    """
    Backfill FindingGroupDailySummary from completed scans.

    Iterates over completed scans and aggregates findings by check_id
    to create daily summary records.

    Args:
        tenant_id: Tenant that owns the scans.
        days: Optional limit on how many days back to backfill.

    Returns:
        dict: Statistics about the backfill operation.
    """
    scans_processed = 0
    scans_skipped = 0
    total_created = 0
    total_updated = 0

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        scan_filter = {
            "tenant_id": tenant_id,
            "state": StateChoices.COMPLETED,
            "completed_at__isnull": False,
        }

        if days is not None:
            cutoff_date = timezone.now() - timedelta(days=days)
            scan_filter["completed_at__gte"] = cutoff_date

        completed_scans = (
            Scan.objects.filter(**scan_filter)
            .order_by("-completed_at")
            .values("id", "completed_at")
        )

        if not completed_scans:
            return {"status": "no scans to backfill"}

        # Keep only latest scan per day
        latest_scans_by_day = {}
        for scan in completed_scans:
            key = scan["completed_at"].date()
            if key not in latest_scans_by_day:
                latest_scans_by_day[key] = scan

    # Process each day's scan
    for scan_date, scan in latest_scans_by_day.items():
        scan_id = str(scan["id"])

        try:
            result = aggregate_finding_group_summaries(tenant_id, scan_id)
            if result.get("status") == "completed":
                scans_processed += 1
                total_created += result.get("created", 0)
                total_updated += result.get("updated", 0)
            else:
                scans_skipped += 1
        except Exception as e:
            logger.warning(
                f"Failed to backfill finding group summaries for scan {scan_id}: {e}"
            )
            scans_skipped += 1

    logger.info(
        f"Backfilled finding group summaries for tenant {tenant_id}: "
        f"{scans_processed} scans processed, {scans_skipped} skipped, "
        f"{total_created} created, {total_updated} updated"
    )

    return {
        "status": "backfilled",
        "scans_processed": scans_processed,
        "scans_skipped": scans_skipped,
        "total_created": total_created,
        "total_updated": total_updated,
    }
