from api.db_utils import rls_transaction
from api.models import Resource, ResourceScanSummary, ResourceFindingMapping, Scan, StateChoices


def backfill_resource_scan_summaries(tenant_id: str, scan_id: str):
    with rls_transaction(tenant_id):
        if ResourceScanSummary.objects.filter(
            tenant_id=tenant_id,
            scan_id=scan_id
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
            ResourceFindingMapping.objects
            .filter(
                tenant_id=tenant_id,
                finding__scan_id=scan_id
            )
            .values_list("resource_id", flat=True)
            .distinct()
        )

        resource_ids = list(resource_ids_qs)

        if not resource_ids:
            return {"status": "no resources to backfill"}

        resources_qs = Resource.objects.filter(
            tenant_id=tenant_id,
            id__in=resource_ids
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
                summaries[i: i + 500],
                ignore_conflicts=True
            )

    return {"status": "backfilled", "inserted": len(summaries)}
