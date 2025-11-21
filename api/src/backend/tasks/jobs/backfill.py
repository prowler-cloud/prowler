from collections import defaultdict

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import (
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    Resource,
    ResourceFindingMapping,
    ResourceScanSummary,
    Scan,
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
