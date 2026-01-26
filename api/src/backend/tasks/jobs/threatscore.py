from celery.utils.log import get_task_logger
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _calculate_requirements_data_from_statistics,
)

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Provider, StatusChoices
from prowler.lib.check.compliance_models import Compliance

logger = get_task_logger(__name__)


def compute_threatscore_metrics(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    compliance_id: str,
    min_risk_level: int = 4,
) -> dict:
    """
    Compute ThreatScore metrics for a given scan.

    This function calculates all the metrics needed for a ThreatScore snapshot:
    - Overall ThreatScore percentage
    - Section-by-section scores
    - Critical failed requirements (risk >= min_risk_level)
    - Summary statistics (requirements and findings counts)

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to analyze.
        provider_id (str): The ID of the provider used in the scan.
        compliance_id (str): Compliance framework ID (e.g., "prowler_threatscore_aws").
        min_risk_level (int): Minimum risk level for critical requirements. Defaults to 4.

    Returns:
        dict: A dictionary containing:
            - overall_score (float): Overall ThreatScore percentage (0-100)
            - section_scores (dict): Section name -> score percentage mapping
            - critical_requirements (list): List of critical failed requirement dicts
            - total_requirements (int): Total number of requirements
            - passed_requirements (int): Number of PASS requirements
            - failed_requirements (int): Number of FAIL requirements
            - manual_requirements (int): Number of MANUAL requirements
            - total_findings (int): Total findings count
            - passed_findings (int): Passed findings count
            - failed_findings (int): Failed findings count

    Example:
        >>> metrics = compute_threatscore_metrics(
        ...     tenant_id="tenant-123",
        ...     scan_id="scan-456",
        ...     provider_id="provider-789",
        ...     compliance_id="prowler_threatscore_aws"
        ... )
        >>> print(f"Overall ThreatScore: {metrics['overall_score']:.2f}%")
    """
    # Get provider and compliance information
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        provider_obj = Provider.objects.get(id=provider_id)
        provider_type = provider_obj.provider

        frameworks_bulk = Compliance.get_bulk(provider_type)
        compliance_obj = frameworks_bulk[compliance_id]

    # Aggregate requirement statistics from database
    requirement_statistics_by_check_id = (
        _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
    )

    # Calculate requirements data using aggregated statistics
    attributes_by_requirement_id, requirements_list = (
        _calculate_requirements_data_from_statistics(
            compliance_obj, requirement_statistics_by_check_id
        )
    )

    # Initialize metrics
    overall_numerator = 0
    overall_denominator = 0
    overall_has_findings = False

    sections_data = {}

    total_requirements = len(requirements_list)
    passed_requirements = 0
    failed_requirements = 0
    manual_requirements = 0
    total_findings = 0
    passed_findings = 0
    failed_findings = 0

    critical_requirements_list = []

    # Process each requirement
    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_status = requirement["attributes"]["status"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        # Count requirements by status
        if requirement_status == StatusChoices.PASS:
            passed_requirements += 1
        elif requirement_status == StatusChoices.FAIL:
            failed_requirements += 1
        elif requirement_status == StatusChoices.MANUAL:
            manual_requirements += 1

        # Get findings data
        req_passed_findings = requirement["attributes"].get("passed_findings", 0)
        req_total_findings = requirement["attributes"].get("total_findings", 0)

        # Accumulate findings counts
        total_findings += req_total_findings
        passed_findings += req_passed_findings
        failed_findings += req_total_findings - req_passed_findings

        # Skip requirements with no findings
        if req_total_findings == 0:
            continue

        overall_has_findings = True

        # Get requirement metadata
        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if not metadata or len(metadata) == 0:
            continue

        m = metadata[0]
        risk_level_raw = getattr(m, "LevelOfRisk", 0)
        weight_raw = getattr(m, "Weight", 0)
        section = getattr(m, "Section", "Unknown")
        risk_level = int(risk_level_raw) if risk_level_raw else 0
        weight = int(weight_raw) if weight_raw else 0

        # Calculate ThreatScore components using formula from UI
        rate_i = req_passed_findings / req_total_findings
        rfac_i = 1 + 0.25 * risk_level

        # Update overall score
        overall_numerator += rate_i * req_total_findings * weight * rfac_i
        overall_denominator += req_total_findings * weight * rfac_i

        # Update section scores
        if section not in sections_data:
            sections_data[section] = {
                "numerator": 0,
                "denominator": 0,
                "has_findings": False,
            }

        sections_data[section]["has_findings"] = True
        sections_data[section]["numerator"] += (
            rate_i * req_total_findings * weight * rfac_i
        )
        sections_data[section]["denominator"] += req_total_findings * weight * rfac_i

        # Identify critical failed requirements
        if requirement_status == StatusChoices.FAIL and risk_level >= min_risk_level:
            critical_requirements_list.append(
                {
                    "requirement_id": requirement_id,
                    "title": getattr(m, "Title", "N/A"),
                    "section": section,
                    "subsection": getattr(m, "SubSection", "N/A"),
                    "risk_level": risk_level,
                    "weight": weight,
                    "passed_findings": req_passed_findings,
                    "total_findings": req_total_findings,
                    "description": getattr(m, "AttributeDescription", "N/A"),
                }
            )

    # Calculate overall ThreatScore
    if not overall_has_findings:
        overall_score = 100.0
    elif overall_denominator > 0:
        overall_score = (overall_numerator / overall_denominator) * 100
    else:
        overall_score = 0.0

    # Calculate section scores
    section_scores = {}
    for section, data in sections_data.items():
        if data["has_findings"] and data["denominator"] > 0:
            section_scores[section] = (data["numerator"] / data["denominator"]) * 100
        else:
            section_scores[section] = 100.0

    # Sort critical requirements by risk level (desc) and weight (desc)
    critical_requirements_list.sort(
        key=lambda x: (x["risk_level"], x["weight"]), reverse=True
    )

    logger.info(
        f"ThreatScore computed: {overall_score:.2f}% "
        f"({passed_requirements}/{total_requirements} requirements passed, "
        f"{len(critical_requirements_list)} critical failures)"
    )

    return {
        "overall_score": round(overall_score, 2),
        "section_scores": {k: round(v, 2) for k, v in section_scores.items()},
        "critical_requirements": critical_requirements_list,
        "total_requirements": total_requirements,
        "passed_requirements": passed_requirements,
        "failed_requirements": failed_requirements,
        "manual_requirements": manual_requirements,
        "total_findings": total_findings,
        "passed_findings": passed_findings,
        "failed_findings": failed_findings,
    }
