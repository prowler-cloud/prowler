from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from django.db.models import Count, F, Q, Window
from django.db.models.functions import RowNumber
from tasks.jobs.reports.config import MAX_FINDINGS_PER_CHECK

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Scan, StatusChoices
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)


def _aggregate_requirement_statistics_from_database(
    tenant_id: str, scan_id: str
) -> dict[str, dict[str, int]]:
    """
    Aggregate finding statistics by check_id using database aggregation.

    This function uses Django ORM aggregation to calculate pass/fail statistics
    entirely in the database, avoiding the need to load findings into memory.

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to retrieve findings for.

    Returns:
        dict[str, dict[str, int]]: Dictionary mapping check_id to statistics:
            - 'passed' (int): Number of passed findings for this check
            - 'total' (int): Total number of findings for this check

    Example:
        {
            'aws_iam_user_mfa_enabled': {'passed': 10, 'total': 15},
            'aws_s3_bucket_public_access': {'passed': 0, 'total': 5}
        }
    """
    requirement_statistics_by_check_id = {}
    # TODO: review when finding-resource relation changes from 1:1
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        # Pre-check: skip if the scan's provider is deleted (avoids JOINs in the main query)
        if Scan.all_objects.filter(id=scan_id, provider__is_deleted=True).exists():
            return requirement_statistics_by_check_id

        aggregated_statistics_queryset = (
            Finding.all_objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
                muted=False,
            )
            .values("check_id")
            .annotate(
                total_findings=Count(
                    "id",
                    filter=Q(status__in=[StatusChoices.PASS, StatusChoices.FAIL]),
                ),
                passed_findings=Count(
                    "id",
                    filter=Q(status=StatusChoices.PASS),
                ),
            )
        )

        for aggregated_stat in aggregated_statistics_queryset:
            check_id = aggregated_stat["check_id"]
            requirement_statistics_by_check_id[check_id] = {
                "passed": aggregated_stat["passed_findings"],
                "total": aggregated_stat["total_findings"],
            }

    logger.info(
        f"Aggregated statistics for {len(requirement_statistics_by_check_id)} unique checks"
    )
    return requirement_statistics_by_check_id


def _calculate_requirements_data_from_statistics(
    compliance_obj, requirement_statistics_by_check_id: dict[str, dict[str, int]]
) -> tuple[dict[str, dict], list[dict]]:
    """
    Calculate requirement status and statistics using pre-aggregated database statistics.

    Args:
        compliance_obj: The compliance framework object containing requirements.
        requirement_statistics_by_check_id (dict[str, dict[str, int]]): Pre-aggregated statistics
            mapping check_id to {'passed': int, 'total': int} counts.

    Returns:
        tuple[dict[str, dict], list[dict]]: A tuple containing:
            - attributes_by_requirement_id: Dictionary mapping requirement IDs to their attributes.
            - requirements_list: List of requirement dictionaries with status and statistics.
    """
    attributes_by_requirement_id = {}
    requirements_list = []

    compliance_framework = getattr(compliance_obj, "Framework", "N/A")
    compliance_version = getattr(compliance_obj, "Version", "N/A")

    for requirement in compliance_obj.Requirements:
        requirement_id = requirement.Id
        requirement_description = getattr(requirement, "Description", "")
        requirement_checks = getattr(requirement, "Checks", [])
        requirement_attributes = getattr(requirement, "Attributes", [])

        attributes_by_requirement_id[requirement_id] = {
            "attributes": {
                "req_attributes": requirement_attributes,
                "checks": requirement_checks,
            },
            "description": requirement_description,
        }

        total_passed_findings = 0
        total_findings_count = 0

        for check_id in requirement_checks:
            if check_id in requirement_statistics_by_check_id:
                check_statistics = requirement_statistics_by_check_id[check_id]
                total_findings_count += check_statistics["total"]
                total_passed_findings += check_statistics["passed"]

        if total_findings_count > 0:
            if total_passed_findings == total_findings_count:
                requirement_status = StatusChoices.PASS
            else:
                requirement_status = StatusChoices.FAIL
        elif requirement_checks:
            # Requirement has checks but none produced findings — consistent
            # with the dashboard's scan processing which treats this as PASS
            # (no failed checks means the requirement is considered compliant).
            requirement_status = StatusChoices.PASS
        else:
            requirement_status = StatusChoices.MANUAL

        requirements_list.append(
            {
                "id": requirement_id,
                "attributes": {
                    "framework": compliance_framework,
                    "version": compliance_version,
                    "status": requirement_status,
                    "description": requirement_description,
                    "passed_findings": total_passed_findings,
                    "total_findings": total_findings_count,
                },
            }
        )

    return attributes_by_requirement_id, requirements_list


def _load_findings_for_requirement_checks(
    tenant_id: str,
    scan_id: str,
    check_ids: list[str],
    prowler_provider,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
    total_counts_out: dict[str, int] | None = None,
    only_failed_findings: bool = False,
) -> dict[str, list[FindingOutput]]:
    """
    Load findings for specific check IDs on-demand with optional caching.

    This function loads only the findings needed for a specific set of checks,
    minimizing memory usage by avoiding loading all findings at once. This is used
    when generating detailed findings tables for specific requirements in the PDF.

    Supports optional caching to avoid duplicate queries when generating multiple
    reports for the same scan.

    Memory optimizations:
    - Uses database iterator with chunk_size for streaming large result sets
    - Shares references between cache and return dict (no duplication)
    - Only selects required fields from database
    - Processes findings in batches to reduce memory pressure

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to retrieve findings for.
        check_ids (list[str]): List of check IDs to load findings for.
        prowler_provider: The initialized Prowler provider instance.
        findings_cache (dict, optional): Cache of already loaded findings.
            If provided, checks are first looked up in cache before querying database.
        total_counts_out (dict, optional): If provided, populated with
            ``{check_id: total_findings_in_db}`` BEFORE any per-check cap is
            applied. Lets callers render a "Showing first N of M" banner for
            truncated checks. Only populated for ``check_ids`` actually
            queried (cache hits keep whatever value the caller already had).
            When ``only_failed_findings=True`` the total is FAIL-only.
        only_failed_findings (bool): When True, push the ``status=FAIL``
            filter down into the SQL query so PASS rows are never loaded
            from the DB nor pydantic-transformed. This matches the
            ``only_failed`` requirement-level filter applied at PDF render
            time: a requirement marked FAIL because 1/1000 findings failed
            shouldn't render a table of 999 PASS rows. That hides the
            actual failure under noise and wastes the per-check cap on
            irrelevant data. NOTE: the findings cache stores whatever the
            first caller asked for, so all callers in a single
            ``generate_compliance_reports`` run MUST pass the same flag
            (which they do: it threads from ``only_failed`` defaults).

    Returns:
        dict[str, list[FindingOutput]]: Dictionary mapping check_id to list of FindingOutput objects.

    Example:
        {
            'aws_iam_user_mfa_enabled': [FindingOutput(...), FindingOutput(...)],
            'aws_s3_bucket_public_access': [FindingOutput(...)]
        }
    """
    if not check_ids:
        return {}

    # Initialize cache if not provided
    if findings_cache is None:
        findings_cache = {}

    # Deduplicate check_ids to avoid redundant processing
    unique_check_ids = list(set(check_ids))

    # Separate cached and non-cached check_ids
    check_ids_to_load = []
    cache_hits = 0

    for check_id in unique_check_ids:
        if check_id in findings_cache:
            cache_hits += 1
        else:
            check_ids_to_load.append(check_id)

    if cache_hits > 0:
        total_checks = len(unique_check_ids)
        logger.info(
            f"Findings cache: {cache_hits}/{total_checks} hits "
            f"({cache_hits / total_checks * 100:.1f}% hit rate)"
        )

    # Load missing check_ids from database
    if check_ids_to_load:
        logger.info(
            f"Loading findings for {len(check_ids_to_load)} checks from database"
        )

        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
            base_qs = Finding.all_objects.filter(
                tenant_id=tenant_id,
                scan_id=scan_id,
                check_id__in=check_ids_to_load,
            )
            if only_failed_findings:
                # Push the FAIL filter down into SQL: DB returns ~N×FAIL
                # rows instead of N×ALL, and we never spend pydantic CPU on
                # PASS findings the PDF would never render.
                base_qs = base_qs.filter(status=StatusChoices.FAIL)

            # Aggregate totals once so we (a) know which checks need capping
            # and (b) can surface "Showing first N of M" in the PDF banner.
            # Cheap: a single COUNT grouped by check_id.
            totals: dict[str, int] = {
                row["check_id"]: row["total"]
                for row in base_qs.values("check_id").annotate(total=Count("id"))
            }
            if total_counts_out is not None:
                total_counts_out.update(totals)

            cap = MAX_FINDINGS_PER_CHECK
            checks_over_cap = (
                {cid for cid, n in totals.items() if n > cap} if cap > 0 else set()
            )

            # Use iterator with chunk_size for memory-efficient streaming.
            # FindingOutput.transform_api_finding (prowler/lib/outputs/finding.py)
            # reads finding.resources.first() and resource.tags.all() per
            # finding, which without prefetch generates 2N queries per chunk.
            # prefetch_related runs once per iterator chunk (Django >=4.1) and
            # collapses that into a constant 2 extra queries per chunk.
            if checks_over_cap:
                # Two-step query so we can both cap rows per check AND attach
                # prefetch_related on the streamed results:
                #
                #   1) ``ranked`` annotates every matching finding with a
                #      per-check row number via a window function. The
                #      partition keeps numbering independent per check, and
                #      ordering by ``uid`` makes the "first N" selection
                #      deterministic across runs (same scan → same rows).
                #
                #   2) The outer ``Finding.all_objects.filter(id__in=...)``
                #      keeps only IDs whose row number is within the cap and
                #      re-opens a plain queryset on it. Django cannot combine
                #      ``Window`` annotations with ``prefetch_related`` on the
                #      same queryset (the window is evaluated post-aggregation
                #      and the prefetch loader fights with it), so the inner
                #      SELECT becomes a subquery and the outer queryset is
                #      free to prefetch resources/tags as usual.
                #
                # PostgreSQL only materialises
                # ``cap * |checks_over_cap| + sum(uncapped)`` rows for the
                # window step, vs the full table scan the previous path did.
                ranked = base_qs.annotate(
                    rn=Window(
                        expression=RowNumber(),
                        partition_by=[F("check_id")],
                        order_by=F("uid").asc(),
                    )
                )
                findings_queryset = (
                    Finding.all_objects.filter(
                        id__in=ranked.filter(rn__lte=cap).values("id")
                    )
                    .prefetch_related("resources", "resources__tags")
                    .order_by("check_id", "uid")
                    .iterator(chunk_size=DJANGO_FINDINGS_BATCH_SIZE)
                )
                logger.info(
                    "Per-check cap=%d active for %d checks (max %d each); "
                    "skipping transform for surplus rows",
                    cap,
                    len(checks_over_cap),
                    cap,
                )
            else:
                findings_queryset = (
                    base_qs.prefetch_related("resources", "resources__tags")
                    .order_by("check_id", "uid")
                    .iterator(chunk_size=DJANGO_FINDINGS_BATCH_SIZE)
                )

            # Pre-initialize empty lists for all check_ids to load
            # This avoids repeated dict lookups and 'if not in' checks
            for check_id in check_ids_to_load:
                findings_cache[check_id] = []

            findings_count = 0
            for finding_model in findings_queryset:
                finding_output = FindingOutput.transform_api_finding(
                    finding_model, prowler_provider
                )
                findings_cache[finding_output.check_id].append(finding_output)
                findings_count += 1

            logger.info(
                "Loaded %d findings for %d checks (truncated %d checks total=%d)",
                findings_count,
                len(check_ids_to_load),
                len(checks_over_cap),
                sum(totals.values()),
            )

    # Build result dict using cache references (no data duplication)
    # This shares the same list objects between cache and result
    result = {
        check_id: findings_cache.get(check_id, []) for check_id in unique_check_ids
    }

    return result


def _get_compliance_check_ids(compliance_obj) -> set[str]:
    """Return the union of all check_ids referenced by a compliance framework.

    Used by the master report orchestrator to evict entries from
    ``findings_cache`` once no pending framework needs them (PROWLER-1733).

    Accepts the legacy ``Compliance`` shape (``Requirements`` / ``Checks``
    lists) and the universal ``ComplianceFramework`` shape (``requirements``
    / ``checks`` dict keyed by provider). ``None`` returns an empty set so
    callers can pass ``frameworks_bulk.get(...)`` directly.
    """
    if compliance_obj is None:
        return set()

    requirements = getattr(compliance_obj, "Requirements", None) or getattr(
        compliance_obj, "requirements", None
    )
    if not requirements:
        return set()

    check_ids: set[str] = set()
    try:
        # Mock objects in unit tests return another Mock for any attribute
        # access — truthy but not iterable. Treat that as "no checks".
        for requirement in requirements:
            requirement_checks = getattr(requirement, "Checks", None)
            if requirement_checks is None:
                checks_by_provider = getattr(requirement, "checks", None) or {}
                requirement_checks = [
                    check_id
                    for check_ids_list in checks_by_provider.values()
                    for check_id in check_ids_list
                ]
            try:
                check_ids.update(requirement_checks)
            except TypeError:
                continue
    except TypeError:
        return set()
    return check_ids
