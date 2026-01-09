# Example: SQL Optimization Patterns
# Source: api/src/backend/api/v1/views.py, api/src/backend/api/mixins.py


from django.conf import settings
from django.contrib.postgres.search import SearchQuery, SearchRank
from django.db.models import OuterRef, Prefetch, Subquery, Sum
from django.db.models.functions import Coalesce

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Resource, ResourceTag, Scan, ScanSummary
from api.uuid_utils import uuid7_end, uuid7_start

# =============================================================================
# 1. UUIDv7 Range Filtering - Critical for partitioned Finding table
# =============================================================================


def filter_findings_by_scan(queryset, scan_id):
    """
    Filter partitioned Finding table efficiently using UUIDv7 range.

    Finding table is partitioned by UUIDv7 id (contains timestamp).
    Use uuid7_start/uuid7_end to compute partition range from scan_id.
    """
    # scan_id is a UUIDv7 - compute partition range
    start_uuid = uuid7_start(scan_id)
    end_uuid = uuid7_end(scan_id, settings.FINDINGS_TABLE_PARTITION_MONTHS)

    return queryset.filter(id__gte=start_uuid, id__lt=end_uuid, scan_id=scan_id)


# =============================================================================
# 2. Full-Text Search - PostgreSQL tsvector
# =============================================================================


def search_resources(queryset, search_term):
    """
    Full-text search on Resource using pre-computed SearchVectorField.

    Resource.text_search is a GeneratedField containing:
    - uid, name, region, service, resource_type
    """
    if not search_term:
        return queryset

    search_query = SearchQuery(search_term, config="simple", search_type="plain")
    return queryset.filter(text_search=search_query)


def search_with_ranking(queryset, search_term):
    """Full-text search with relevance ranking."""
    search_query = SearchQuery(search_term, config="simple")
    return (
        queryset.annotate(rank=SearchRank("text_search", search_query))
        .filter(text_search=search_query)
        .order_by("-rank")
    )


# =============================================================================
# 3. prefetch_for_includes - Dynamic prefetching based on ?include= param
# =============================================================================


class OptimizedResourceViewSet:
    """Example ViewSet with dynamic prefetching."""

    prefetch_for_includes = {
        "__all__": [],
        "findings": [
            Prefetch(
                "findings",
                queryset=Finding.all_objects.defer("raw_result", "resources"),
            )
        ],
        "tags": [Prefetch("tags", queryset=ResourceTag.objects.all())],
        "scan": [Prefetch("scan", queryset=Scan.objects.select_related("provider"))],
    }

    def get_queryset(self):
        queryset = super().get_queryset()

        includes = self.request.query_params.get("include", "").split(",")
        includes = [i.strip() for i in includes if i.strip()]

        queryset = queryset.prefetch_related(*self.prefetch_for_includes["__all__"])

        for include in includes:
            if include in self.prefetch_for_includes:
                queryset = queryset.prefetch_related(
                    *self.prefetch_for_includes[include]
                )

        return queryset


# =============================================================================
# 4. Read Replica Usage - Heavy read operations
# =============================================================================


def get_findings_from_replica(tenant_id, scan_id):
    """Read heavy data from replica to reduce primary load."""
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        return list(
            Finding.objects.filter(scan_id=scan_id)
            .select_related("scan__provider")
            .prefetch_related("resources")
        )


# =============================================================================
# 5. Aggregations - Use summary tables, not raw aggregates
# =============================================================================


def get_scan_statistics(scan_id):
    """
    Read from pre-aggregated ScanSummary table.
    perform_scan_summary_task populates this after each scan.

    AVOID aggregating Finding table directly - can have millions of rows.
    """
    return ScanSummary.objects.filter(scan_id=scan_id).aggregate(
        passed=Coalesce(Sum("_pass"), 0),
        failed=Coalesce(Sum("fail"), 0),
        muted=Coalesce(Sum("muted"), 0),
        total=Coalesce(Sum("total"), 0),
    )


# =============================================================================
# 6. Bulk Operations - Efficient batch processing
# =============================================================================


BATCH_SIZE = 500


def bulk_create_findings(findings_data, tenant_id, scan):
    """Bulk create findings efficiently."""
    findings_to_create = [
        Finding(
            tenant_id=tenant_id,
            scan=scan,
            check_id=f["check_id"],
            status=f["status"],
            severity=f["severity"],
        )
        for f in findings_data
    ]

    Finding.objects.bulk_create(findings_to_create, batch_size=BATCH_SIZE)


def bulk_update_status(finding_ids, new_status, tenant_id):
    """Bulk update using queryset update (single SQL query)."""
    with rls_transaction(tenant_id):
        return Finding.objects.filter(id__in=finding_ids).update(status=new_status)


# =============================================================================
# 7. Subqueries - Efficient related data lookups
# =============================================================================


def get_resources_with_latest_finding_status(tenant_id):
    """Get resources annotated with their latest finding status."""
    latest_finding = (
        Finding.objects.filter(resources=OuterRef("pk"))
        .order_by("-inserted_at")
        .values("status")[:1]
    )

    return Resource.objects.filter(tenant_id=tenant_id).annotate(
        latest_status=Subquery(latest_finding)
    )


# =============================================================================
# 8. Index Best Practices
# =============================================================================


"""
INDEX RULES:

1. tenant_id FIRST in composite indexes (for RLS):
   Index(fields=["tenant_id", "provider_id"])  # Good
   Index(fields=["provider_id", "tenant_id"])  # Bad

2. Partial indexes for common filters:
   Index(fields=["tenant_id", "id"], condition=Q(delta="new"))

3. GIN for arrays and full-text:
   GinIndex(fields=["text_search"])
   GinIndex(fields=["resource_regions"])
"""
