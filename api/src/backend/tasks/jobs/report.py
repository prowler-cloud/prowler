"""
Compliance PDF Report Generation.

This module provides functions for generating PDF compliance reports
using the modular report generation framework.
"""

from pathlib import Path
from shutil import rmtree

from celery.utils.log import get_task_logger
from config.django.base import DJANGO_TMP_OUTPUT_DIRECTORY
from tasks.jobs.export import _generate_compliance_output_directory, _upload_to_s3
from tasks.jobs.reports import (
    FRAMEWORK_REGISTRY,
    ENSReportGenerator,
    NIS2ReportGenerator,
    ThreatScoreReportGenerator,
)
from tasks.jobs.threatscore import compute_threatscore_metrics
from tasks.jobs.threatscore_utils import _aggregate_requirement_statistics_from_database

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Provider, ScanSummary, ThreatScoreSnapshot
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)


def generate_threatscore_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    only_failed: bool = True,
    min_risk_level: int = 4,
    provider_obj: Provider | None = None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
) -> None:
    """
    Generate a PDF compliance report based on Prowler ThreatScore framework.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: ID of the scan executed by Prowler.
        compliance_id: ID of the compliance framework (e.g., "prowler_threatscore_aws").
        output_path: Output PDF file path.
        provider_id: Provider ID for the scan.
        only_failed: If True, only include failed requirements in detailed section.
        min_risk_level: Minimum risk level for critical failed requirements.
        provider_obj: Pre-fetched Provider object to avoid duplicate queries.
        requirement_statistics: Pre-aggregated requirement statistics.
        findings_cache: Cache of already loaded findings to avoid duplicate queries.
    """
    generator = ThreatScoreReportGenerator(FRAMEWORK_REGISTRY["prowler_threatscore"])
    generator._min_risk_level = min_risk_level

    generator.generate(
        tenant_id=tenant_id,
        scan_id=scan_id,
        compliance_id=compliance_id,
        output_path=output_path,
        provider_id=provider_id,
        provider_obj=provider_obj,
        requirement_statistics=requirement_statistics,
        findings_cache=findings_cache,
        only_failed=only_failed,
    )


def generate_ens_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    include_manual: bool = True,
    provider_obj: Provider | None = None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
) -> None:
    """
    Generate a PDF compliance report for ENS RD2022 framework.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: ID of the scan executed by Prowler.
        compliance_id: ID of the compliance framework (e.g., "ens_rd2022_aws").
        output_path: Output PDF file path.
        provider_id: Provider ID for the scan.
        include_manual: If True, include manual requirements in detailed section.
        provider_obj: Pre-fetched Provider object to avoid duplicate queries.
        requirement_statistics: Pre-aggregated requirement statistics.
        findings_cache: Cache of already loaded findings to avoid duplicate queries.
    """
    generator = ENSReportGenerator(FRAMEWORK_REGISTRY["ens"])

    generator.generate(
        tenant_id=tenant_id,
        scan_id=scan_id,
        compliance_id=compliance_id,
        output_path=output_path,
        provider_id=provider_id,
        provider_obj=provider_obj,
        requirement_statistics=requirement_statistics,
        findings_cache=findings_cache,
        include_manual=include_manual,
    )


def generate_nis2_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    only_failed: bool = True,
    include_manual: bool = False,
    provider_obj: Provider | None = None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
) -> None:
    """
    Generate a PDF compliance report for NIS2 Directive (EU) 2022/2555.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: ID of the scan executed by Prowler.
        compliance_id: ID of the compliance framework (e.g., "nis2_aws").
        output_path: Output PDF file path.
        provider_id: Provider ID for the scan.
        only_failed: If True, only include failed requirements in detailed section.
        include_manual: If True, include manual requirements in detailed section.
        provider_obj: Pre-fetched Provider object to avoid duplicate queries.
        requirement_statistics: Pre-aggregated requirement statistics.
        findings_cache: Cache of already loaded findings to avoid duplicate queries.
    """
    generator = NIS2ReportGenerator(FRAMEWORK_REGISTRY["nis2"])

    generator.generate(
        tenant_id=tenant_id,
        scan_id=scan_id,
        compliance_id=compliance_id,
        output_path=output_path,
        provider_id=provider_id,
        provider_obj=provider_obj,
        requirement_statistics=requirement_statistics,
        findings_cache=findings_cache,
        only_failed=only_failed,
        include_manual=include_manual,
    )


def generate_compliance_reports(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    generate_threatscore: bool = True,
    generate_ens: bool = True,
    generate_nis2: bool = True,
    only_failed_threatscore: bool = True,
    min_risk_level_threatscore: int = 4,
    include_manual_ens: bool = True,
    include_manual_nis2: bool = False,
    only_failed_nis2: bool = True,
) -> dict[str, dict[str, bool | str]]:
    """
    Generate multiple compliance reports with shared database queries.

    This function optimizes the generation of multiple reports by:
    - Fetching the provider object once
    - Aggregating requirement statistics once (shared across all reports)
    - Reusing compliance framework data when possible

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: The ID of the scan to generate reports for.
        provider_id: The ID of the provider used in the scan.
        generate_threatscore: Whether to generate ThreatScore report.
        generate_ens: Whether to generate ENS report.
        generate_nis2: Whether to generate NIS2 report.
        only_failed_threatscore: For ThreatScore, only include failed requirements.
        min_risk_level_threatscore: Minimum risk level for ThreatScore critical requirements.
        include_manual_ens: For ENS, include manual requirements.
        include_manual_nis2: For NIS2, include manual requirements.
        only_failed_nis2: For NIS2, only include failed requirements.

    Returns:
        Dictionary with results for each report type.
    """
    logger.info(
        f"Generating compliance reports for scan {scan_id} with provider {provider_id}"
        f" (ThreatScore: {generate_threatscore}, ENS: {generate_ens}, NIS2: {generate_nis2})"
    )

    results = {}

    # Validate that the scan has findings and get provider info
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if not ScanSummary.objects.filter(scan_id=scan_id).exists():
            logger.info(f"No findings found for scan {scan_id}")
            if generate_threatscore:
                results["threatscore"] = {"upload": False, "path": ""}
            if generate_ens:
                results["ens"] = {"upload": False, "path": ""}
            if generate_nis2:
                results["nis2"] = {"upload": False, "path": ""}
            return results

        provider_obj = Provider.objects.get(id=provider_id)
        provider_uid = provider_obj.uid
        provider_type = provider_obj.provider

    # Check provider compatibility
    if generate_threatscore and provider_type not in [
        "aws",
        "azure",
        "gcp",
        "m365",
        "kubernetes",
    ]:
        logger.info(f"Provider {provider_type} not supported for ThreatScore report")
        results["threatscore"] = {"upload": False, "path": ""}
        generate_threatscore = False

    if generate_ens and provider_type not in ["aws", "azure", "gcp"]:
        logger.info(f"Provider {provider_type} not supported for ENS report")
        results["ens"] = {"upload": False, "path": ""}
        generate_ens = False

    if generate_nis2 and provider_type not in ["aws", "azure", "gcp"]:
        logger.info(f"Provider {provider_type} not supported for NIS2 report")
        results["nis2"] = {"upload": False, "path": ""}
        generate_nis2 = False

    if not generate_threatscore and not generate_ens and not generate_nis2:
        return results

    # Aggregate requirement statistics once
    logger.info(
        f"Aggregating requirement statistics once for all reports (scan {scan_id})"
    )
    requirement_statistics = _aggregate_requirement_statistics_from_database(
        tenant_id, scan_id
    )

    # Create shared findings cache
    findings_cache = {}
    logger.info("Created shared findings cache for all reports")

    # Generate output directories
    try:
        logger.info("Generating output directories")
        threatscore_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="threatscore",
        )
        ens_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="ens",
        )
        nis2_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="nis2",
        )
        out_dir = str(Path(threatscore_path).parent.parent)
    except Exception as e:
        logger.error(f"Error generating output directory: {e}")
        error_dict = {"error": str(e), "upload": False, "path": ""}
        if generate_threatscore:
            results["threatscore"] = error_dict.copy()
        if generate_ens:
            results["ens"] = error_dict.copy()
        if generate_nis2:
            results["nis2"] = error_dict.copy()
        return results

    # Generate ThreatScore report
    if generate_threatscore:
        compliance_id_threatscore = f"prowler_threatscore_{provider_type}"
        pdf_path_threatscore = f"{threatscore_path}_threatscore_report.pdf"
        logger.info(
            f"Generating ThreatScore report with compliance {compliance_id_threatscore}"
        )

        try:
            generate_threatscore_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_threatscore,
                output_path=pdf_path_threatscore,
                provider_id=provider_id,
                only_failed=only_failed_threatscore,
                min_risk_level=min_risk_level_threatscore,
                provider_obj=provider_obj,
                requirement_statistics=requirement_statistics,
                findings_cache=findings_cache,
            )

            # Compute and store ThreatScore metrics snapshot
            logger.info(f"Computing ThreatScore metrics for scan {scan_id}")
            try:
                metrics = compute_threatscore_metrics(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    provider_id=provider_id,
                    compliance_id=compliance_id_threatscore,
                    min_risk_level=min_risk_level_threatscore,
                )

                with rls_transaction(tenant_id):
                    previous_snapshot = (
                        ThreatScoreSnapshot.objects.filter(
                            tenant_id=tenant_id,
                            provider_id=provider_id,
                            compliance_id=compliance_id_threatscore,
                        )
                        .order_by("-inserted_at")
                        .first()
                    )

                    score_delta = None
                    if previous_snapshot:
                        score_delta = metrics["overall_score"] - float(
                            previous_snapshot.overall_score
                        )

                    snapshot = ThreatScoreSnapshot.objects.create(
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        provider_id=provider_id,
                        compliance_id=compliance_id_threatscore,
                        overall_score=metrics["overall_score"],
                        score_delta=score_delta,
                        section_scores=metrics["section_scores"],
                        critical_requirements=metrics["critical_requirements"],
                        total_requirements=metrics["total_requirements"],
                        passed_requirements=metrics["passed_requirements"],
                        failed_requirements=metrics["failed_requirements"],
                        manual_requirements=metrics["manual_requirements"],
                        total_findings=metrics["total_findings"],
                        passed_findings=metrics["passed_findings"],
                        failed_findings=metrics["failed_findings"],
                    )

                    delta_msg = (
                        f" (delta: {score_delta:+.2f}%)"
                        if score_delta is not None
                        else ""
                    )
                    logger.info(
                        f"ThreatScore snapshot created with ID {snapshot.id} (score: {snapshot.overall_score}%{delta_msg})"
                    )
            except Exception as e:
                logger.error(f"Error creating ThreatScore snapshot: {e}")

            upload_uri_threatscore = _upload_to_s3(
                tenant_id,
                scan_id,
                pdf_path_threatscore,
                f"threatscore/{Path(pdf_path_threatscore).name}",
            )

            if upload_uri_threatscore:
                results["threatscore"] = {
                    "upload": True,
                    "path": upload_uri_threatscore,
                }
                logger.info(f"ThreatScore report uploaded to {upload_uri_threatscore}")
            else:
                results["threatscore"] = {"upload": False, "path": out_dir}
                logger.warning(f"ThreatScore report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating ThreatScore report: {e}")
            results["threatscore"] = {"upload": False, "path": "", "error": str(e)}

    # Generate ENS report
    if generate_ens:
        compliance_id_ens = f"ens_rd2022_{provider_type}"
        pdf_path_ens = f"{ens_path}_ens_report.pdf"
        logger.info(f"Generating ENS report with compliance {compliance_id_ens}")

        try:
            generate_ens_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_ens,
                output_path=pdf_path_ens,
                provider_id=provider_id,
                include_manual=include_manual_ens,
                provider_obj=provider_obj,
                requirement_statistics=requirement_statistics,
                findings_cache=findings_cache,
            )

            upload_uri_ens = _upload_to_s3(
                tenant_id, scan_id, pdf_path_ens, f"ens/{Path(pdf_path_ens).name}"
            )

            if upload_uri_ens:
                results["ens"] = {"upload": True, "path": upload_uri_ens}
                logger.info(f"ENS report uploaded to {upload_uri_ens}")
            else:
                results["ens"] = {"upload": False, "path": out_dir}
                logger.warning(f"ENS report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating ENS report: {e}")
            results["ens"] = {"upload": False, "path": "", "error": str(e)}

    # Generate NIS2 report
    if generate_nis2:
        compliance_id_nis2 = f"nis2_{provider_type}"
        pdf_path_nis2 = f"{nis2_path}_nis2_report.pdf"
        logger.info(f"Generating NIS2 report with compliance {compliance_id_nis2}")

        try:
            generate_nis2_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_nis2,
                output_path=pdf_path_nis2,
                provider_id=provider_id,
                only_failed=only_failed_nis2,
                include_manual=include_manual_nis2,
                provider_obj=provider_obj,
                requirement_statistics=requirement_statistics,
                findings_cache=findings_cache,
            )

            upload_uri_nis2 = _upload_to_s3(
                tenant_id, scan_id, pdf_path_nis2, f"nis2/{Path(pdf_path_nis2).name}"
            )

            if upload_uri_nis2:
                results["nis2"] = {"upload": True, "path": upload_uri_nis2}
                logger.info(f"NIS2 report uploaded to {upload_uri_nis2}")
            else:
                results["nis2"] = {"upload": False, "path": out_dir}
                logger.warning(f"NIS2 report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating NIS2 report: {e}")
            results["nis2"] = {"upload": False, "path": "", "error": str(e)}

    # Clean up temporary files if all reports were uploaded successfully
    all_uploaded = all(
        result.get("upload", False)
        for result in results.values()
        if result.get("upload") is not None
    )

    if all_uploaded:
        try:
            rmtree(Path(out_dir), ignore_errors=True)
            logger.info(f"Cleaned up temporary files at {out_dir}")
        except Exception as e:
            logger.error(f"Error deleting output files: {e}")

    logger.info(f"Compliance reports generation completed. Results: {results}")
    return results


def generate_compliance_reports_job(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    generate_threatscore: bool = True,
    generate_ens: bool = True,
    generate_nis2: bool = True,
) -> dict[str, dict[str, bool | str]]:
    """
    Celery task wrapper for generate_compliance_reports.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: The ID of the scan to generate reports for.
        provider_id: The ID of the provider used in the scan.
        generate_threatscore: Whether to generate ThreatScore report.
        generate_ens: Whether to generate ENS report.
        generate_nis2: Whether to generate NIS2 report.

    Returns:
        Dictionary with results for each report type.
    """
    return generate_compliance_reports(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        generate_threatscore=generate_threatscore,
        generate_ens=generate_ens,
        generate_nis2=generate_nis2,
    )
