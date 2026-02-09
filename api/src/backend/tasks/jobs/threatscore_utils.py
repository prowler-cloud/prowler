from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE
from django.db.models import Count, Q

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, StatusChoices
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

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        aggregated_statistics_queryset = (
            Finding.all_objects.filter(
                tenant_id=tenant_id, scan_id=scan_id, muted=False
            )
            .values("check_id")
            .annotate(
                total_findings=Count(
                    "id",
                    filter=Q(status__in=[StatusChoices.PASS, StatusChoices.FAIL]),
                ),
                passed_findings=Count("id", filter=Q(status=StatusChoices.PASS)),
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
            # Use iterator with chunk_size for memory-efficient streaming
            # chunk_size controls how many rows Django fetches from DB at once
            findings_queryset = (
                Finding.all_objects.filter(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    check_id__in=check_ids_to_load,
                )
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
                f"Loaded {findings_count} findings for {len(check_ids_to_load)} checks"
            )

    # Build result dict using cache references (no data duplication)
    # This shares the same list objects between cache and result
    result = {
        check_id: findings_cache.get(check_id, []) for check_id in unique_check_ids
    }

    return result
