from collections import defaultdict

from django.db.models import Sum

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import (
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    Scan,
    ScanCategorySummary,
    ScanSummary,
    StateChoices,
)


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
    from datetime import timedelta

    from django.utils import timezone

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

    Aggregates unique categories from all findings in the scan and creates
    a single ScanCategorySummary row.

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

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if not Scan.objects.filter(
            tenant_id=tenant_id,
            id=scan_id,
            state__in=(StateChoices.COMPLETED, StateChoices.FAILED),
        ).exists():
            return {"status": "scan is not completed"}

        categories_set = set()
        for categories_list in Finding.all_objects.filter(
            tenant_id=tenant_id, scan_id=scan_id
        ).values_list("categories", flat=True):
            if categories_list:
                categories_set.update(categories_list)

        if not categories_set:
            return {"status": "no categories to backfill"}

    with rls_transaction(tenant_id):
        ScanCategorySummary.objects.update_or_create(
            tenant_id=tenant_id,
            scan_id=scan_id,
            defaults={"categories": sorted(categories_set)},
        )

    return {"status": "backfilled", "categories_count": len(categories_set)}
