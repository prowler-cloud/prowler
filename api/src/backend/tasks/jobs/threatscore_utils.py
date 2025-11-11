from celery.utils.log import get_task_logger
from django.db.models import Count, Q

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, StatusChoices

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
            Finding.all_objects.filter(tenant_id=tenant_id, scan_id=scan_id)
            .values("check_id")
            .annotate(
                total_findings=Count("id"),
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
