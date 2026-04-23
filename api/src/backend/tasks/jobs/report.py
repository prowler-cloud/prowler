import gc
import re
from collections.abc import Iterable
from pathlib import Path
from shutil import rmtree

from celery.utils.log import get_task_logger
from config.django.base import DJANGO_TMP_OUTPUT_DIRECTORY
from tasks.jobs.export import _generate_compliance_output_directory, _upload_to_s3
from tasks.jobs.reports import (
    FRAMEWORK_REGISTRY,
    CISReportGenerator,
    CSAReportGenerator,
    ENSReportGenerator,
    NIS2ReportGenerator,
    ThreatScoreReportGenerator,
)
from tasks.jobs.threatscore import compute_threatscore_metrics
from tasks.jobs.threatscore_utils import _aggregate_requirement_statistics_from_database

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Provider, ScanSummary, ThreatScoreSnapshot
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)

# Matches CIS compliance_ids like "cis_1.4_aws", "cis_5.0_azure",
# "cis_1.10_kubernetes", "cis_3.0.1_aws". Requires at least one dotted
# component so malformed inputs like "cis_._aws" or "cis_5._aws" are rejected
# at the regex stage, rather than by a later ValueError fallback.
_CIS_VARIANT_RE = re.compile(r"^cis_(?P<version>\d+(?:\.\d+)+)_(?P<provider>.+)$")


def _pick_latest_cis_variant(compliance_ids: Iterable[str]) -> str | None:
    """Return the CIS compliance_id with the highest semantic version.

    CIS ships many variants per provider (e.g. cis_1.4_aws, ..., cis_6.0_aws).
    A lexicographic sort is incorrect for version strings like ``1.10`` vs
    ``1.2``; this helper parses the version into a tuple of ints so ``1.10``
    is correctly ordered after ``1.2``. Malformed names are skipped so a
    broken JSON cannot crash the whole CIS pipeline.

    Args:
        compliance_ids: Iterable of CIS compliance identifiers. Expected to
            belong to a single provider (callers should pass the already
            filtered keys from ``Compliance.get_bulk(provider_type)``).

    Returns:
        The compliance_id with the highest parsed version, or ``None`` if no
        well-formed CIS identifier was found.
    """
    best_key: tuple[int, ...] | None = None
    best_name: str | None = None
    for name in compliance_ids:
        match = _CIS_VARIANT_RE.match(name)
        if not match:
            continue
        try:
            key = tuple(int(part) for part in match.group("version").split("."))
        except ValueError:
            # Defensive: the regex already guarantees numeric chunks, but we
            # keep the guard so a future regex change cannot crash callers.
            continue
        if best_key is None or key > best_key:
            best_key = key
            best_name = name
    return best_name


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


def generate_csa_report(
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
    Generate a PDF compliance report for CSA Cloud Controls Matrix (CCM) v4.0.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: ID of the scan executed by Prowler.
        compliance_id: ID of the compliance framework (e.g., "csa_ccm_4.0_aws").
        output_path: Output PDF file path.
        provider_id: Provider ID for the scan.
        only_failed: If True, only include failed requirements in detailed section.
        include_manual: If True, include manual requirements in detailed section.
        provider_obj: Pre-fetched Provider object to avoid duplicate queries.
        requirement_statistics: Pre-aggregated requirement statistics.
        findings_cache: Cache of already loaded findings to avoid duplicate queries.
    """
    generator = CSAReportGenerator(FRAMEWORK_REGISTRY["csa_ccm"])

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


def generate_cis_report(
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
    Generate a PDF compliance report for a specific CIS Benchmark variant.

    Unlike single-version frameworks (ENS, NIS2, CSA), CIS has multiple
    variants per provider (e.g., cis_1.4_aws, cis_5.0_aws, cis_6.0_aws). This
    wrapper is called once per variant, receiving the specific compliance_id.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: ID of the scan executed by Prowler.
        compliance_id: ID of the specific CIS variant (e.g., "cis_5.0_aws").
        output_path: Output PDF file path.
        provider_id: Provider ID for the scan.
        only_failed: If True, only include failed requirements in detailed section.
        include_manual: If True, include manual requirements in detailed section.
        provider_obj: Pre-fetched Provider object to avoid duplicate queries.
        requirement_statistics: Pre-aggregated requirement statistics.
        findings_cache: Cache of already loaded findings to avoid duplicate queries.
    """
    generator = CISReportGenerator(FRAMEWORK_REGISTRY["cis"])

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
    generate_csa: bool = True,
    generate_cis: bool = True,
    only_failed_threatscore: bool = True,
    min_risk_level_threatscore: int = 4,
    include_manual_ens: bool = True,
    include_manual_nis2: bool = False,
    only_failed_nis2: bool = True,
    only_failed_csa: bool = True,
    include_manual_csa: bool = False,
    only_failed_cis: bool = True,
    include_manual_cis: bool = False,
) -> dict[str, dict[str, bool | str]]:
    """
    Generate multiple compliance reports with shared database queries.

    This function optimizes the generation of multiple reports by:
    - Fetching the provider object once
    - Aggregating requirement statistics once (shared across all reports)
    - Reusing compliance framework data when possible

    For CIS a single PDF is produced per run: the one matching the highest
    available CIS version for the scan's provider (picked dynamically from
    ``Compliance.get_bulk`` via :func:`_pick_latest_cis_variant`). The
    returned ``results["cis"]`` entry has the same flat shape as the other
    single-version frameworks — the picked variant is an internal detail,
    not surfaced in the result.

    Args:
        tenant_id: The tenant ID for Row-Level Security context.
        scan_id: The ID of the scan to generate reports for.
        provider_id: The ID of the provider used in the scan.
        generate_threatscore: Whether to generate ThreatScore report.
        generate_ens: Whether to generate ENS report.
        generate_nis2: Whether to generate NIS2 report.
        generate_csa: Whether to generate CSA CCM report.
        generate_cis: Whether to generate a CIS Benchmark report for the
            latest CIS version available for the provider.
        only_failed_threatscore: For ThreatScore, only include failed requirements.
        min_risk_level_threatscore: Minimum risk level for ThreatScore critical requirements.
        include_manual_ens: For ENS, include manual requirements.
        include_manual_nis2: For NIS2, include manual requirements.
        only_failed_nis2: For NIS2, only include failed requirements.
        only_failed_csa: For CSA CCM, only include failed requirements.
        include_manual_csa: For CSA CCM, include manual requirements.
        only_failed_cis: For CIS, only include failed requirements in detailed section.
        include_manual_cis: For CIS, include manual requirements in detailed section.

    Returns:
        Dictionary with results for each report type. Every value has the
        same flat shape: ``{"upload": bool, "path": str, "error"?: str}``.
    """
    logger.info(
        "Generating compliance reports for scan %s with provider %s"
        " (ThreatScore: %s, ENS: %s, NIS2: %s, CSA: %s, CIS: %s)",
        scan_id,
        provider_id,
        generate_threatscore,
        generate_ens,
        generate_nis2,
        generate_csa,
        generate_cis,
    )

    results: dict = {}

    # Validate that the scan has findings and get provider info
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if not ScanSummary.objects.filter(scan_id=scan_id).exists():
            logger.info("No findings found for scan %s", scan_id)
            if generate_threatscore:
                results["threatscore"] = {"upload": False, "path": ""}
            if generate_ens:
                results["ens"] = {"upload": False, "path": ""}
            if generate_nis2:
                results["nis2"] = {"upload": False, "path": ""}
            if generate_csa:
                results["csa"] = {"upload": False, "path": ""}
            if generate_cis:
                results["cis"] = {"upload": False, "path": ""}
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
        "alibabacloud",
    ]:
        logger.info("Provider %s not supported for ThreatScore report", provider_type)
        results["threatscore"] = {"upload": False, "path": ""}
        generate_threatscore = False

    if generate_ens and provider_type not in ["aws", "azure", "gcp"]:
        logger.info("Provider %s not supported for ENS report", provider_type)
        results["ens"] = {"upload": False, "path": ""}
        generate_ens = False

    if generate_nis2 and provider_type not in ["aws", "azure", "gcp"]:
        logger.info("Provider %s not supported for NIS2 report", provider_type)
        results["nis2"] = {"upload": False, "path": ""}
        generate_nis2 = False

    if generate_csa and provider_type not in [
        "aws",
        "azure",
        "gcp",
        "oraclecloud",
        "alibabacloud",
    ]:
        logger.info("Provider %s not supported for CSA CCM report", provider_type)
        results["csa"] = {"upload": False, "path": ""}
        generate_csa = False

    # For CIS we do NOT pre-check the provider against a hard-coded whitelist
    # (that list drifts the moment a new CIS JSON ships). Instead, we let
    # `_pick_latest_cis_variant` over `Compliance.get_bulk(provider_type)`
    # return None for providers that lack CIS, and treat that as "nothing to
    # do" below.

    if (
        not generate_threatscore
        and not generate_ens
        and not generate_nis2
        and not generate_csa
        and not generate_cis
    ):
        return results

    # Aggregate requirement statistics once
    logger.info(
        "Aggregating requirement statistics once for all reports (scan %s)", scan_id
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
        csa_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="csa",
        )
        cis_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="cis",
        )
        out_dir = str(Path(threatscore_path).parent.parent)
    except Exception as e:
        logger.error("Error generating output directory: %s", e)
        error_dict = {"error": str(e), "upload": False, "path": ""}
        if generate_threatscore:
            results["threatscore"] = error_dict.copy()
        if generate_ens:
            results["ens"] = error_dict.copy()
        if generate_nis2:
            results["nis2"] = error_dict.copy()
        if generate_csa:
            results["csa"] = error_dict.copy()
        if generate_cis:
            results["cis"] = error_dict.copy()
        return results

    # Generate ThreatScore report
    if generate_threatscore:
        compliance_id_threatscore = f"prowler_threatscore_{provider_type}"
        pdf_path_threatscore = f"{threatscore_path}_threatscore_report.pdf"
        logger.info(
            "Generating ThreatScore report with compliance %s",
            compliance_id_threatscore,
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
            logger.info("Computing ThreatScore metrics for scan %s", scan_id)
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
                        f"ThreatScore snapshot created with ID {snapshot.id} (score: {snapshot.overall_score}%{delta_msg})",
                    )
            except Exception as e:
                logger.error("Error creating ThreatScore snapshot: %s", e)

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
                logger.info("ThreatScore report uploaded to %s", upload_uri_threatscore)
            else:
                results["threatscore"] = {"upload": False, "path": out_dir}
                logger.warning("ThreatScore report saved locally at %s", out_dir)

        except Exception as e:
            logger.error("Error generating ThreatScore report: %s", e)
            results["threatscore"] = {"upload": False, "path": "", "error": str(e)}

    # Generate ENS report
    if generate_ens:
        compliance_id_ens = f"ens_rd2022_{provider_type}"
        pdf_path_ens = f"{ens_path}_ens_report.pdf"
        logger.info("Generating ENS report with compliance %s", compliance_id_ens)

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
                logger.info("ENS report uploaded to %s", upload_uri_ens)
            else:
                results["ens"] = {"upload": False, "path": out_dir}
                logger.warning("ENS report saved locally at %s", out_dir)

        except Exception as e:
            logger.error("Error generating ENS report: %s", e)
            results["ens"] = {"upload": False, "path": "", "error": str(e)}

    # Generate NIS2 report
    if generate_nis2:
        compliance_id_nis2 = f"nis2_{provider_type}"
        pdf_path_nis2 = f"{nis2_path}_nis2_report.pdf"
        logger.info("Generating NIS2 report with compliance %s", compliance_id_nis2)

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
                logger.info("NIS2 report uploaded to %s", upload_uri_nis2)
            else:
                results["nis2"] = {"upload": False, "path": out_dir}
                logger.warning("NIS2 report saved locally at %s", out_dir)

        except Exception as e:
            logger.error("Error generating NIS2 report: %s", e)
            results["nis2"] = {"upload": False, "path": "", "error": str(e)}

    # Generate CSA CCM report
    if generate_csa:
        compliance_id_csa = f"csa_ccm_4.0_{provider_type}"
        pdf_path_csa = f"{csa_path}_csa_report.pdf"
        logger.info("Generating CSA CCM report with compliance %s", compliance_id_csa)

        try:
            generate_csa_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_csa,
                output_path=pdf_path_csa,
                provider_id=provider_id,
                only_failed=only_failed_csa,
                include_manual=include_manual_csa,
                provider_obj=provider_obj,
                requirement_statistics=requirement_statistics,
                findings_cache=findings_cache,
            )

            upload_uri_csa = _upload_to_s3(
                tenant_id, scan_id, pdf_path_csa, f"csa/{Path(pdf_path_csa).name}"
            )

            if upload_uri_csa:
                results["csa"] = {"upload": True, "path": upload_uri_csa}
                logger.info("CSA CCM report uploaded to %s", upload_uri_csa)
            else:
                results["csa"] = {"upload": False, "path": out_dir}
                logger.warning("CSA CCM report saved locally at %s", out_dir)

        except Exception as e:
            logger.error("Error generating CSA CCM report: %s", e)
            results["csa"] = {"upload": False, "path": "", "error": str(e)}

    # Generate CIS Benchmark report for the latest available version only.
    # CIS ships multiple versions per provider (e.g. cis_1.4_aws, cis_5.0_aws,
    # cis_6.0_aws); we dynamically pick the highest semantic version at run
    # time rather than hard-coding a per-provider mapping. `Compliance.get_bulk`
    # is the single source of truth for which providers have CIS.
    if generate_cis:
        latest_cis: str | None = None
        try:
            frameworks_bulk = Compliance.get_bulk(provider_type)
            latest_cis = _pick_latest_cis_variant(
                name for name in frameworks_bulk.keys() if name.startswith("cis_")
            )
        except Exception as e:
            logger.error("Error discovering CIS variants for %s: %s", provider_type, e)
            results["cis"] = {"upload": False, "path": "", "error": str(e)}

        if "cis" not in results:
            if latest_cis is None:
                logger.info("No CIS variants available for provider %s", provider_type)
                results["cis"] = {"upload": False, "path": ""}
            else:
                logger.info(
                    "Selected latest CIS variant for provider %s: %s",
                    provider_type,
                    latest_cis,
                )
                pdf_path_cis = f"{cis_path}_cis_report.pdf"
                try:
                    generate_cis_report(
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        compliance_id=latest_cis,
                        output_path=pdf_path_cis,
                        provider_id=provider_id,
                        only_failed=only_failed_cis,
                        include_manual=include_manual_cis,
                        provider_obj=provider_obj,
                        requirement_statistics=requirement_statistics,
                        findings_cache=findings_cache,
                    )

                    upload_uri_cis = _upload_to_s3(
                        tenant_id,
                        scan_id,
                        pdf_path_cis,
                        f"cis/{Path(pdf_path_cis).name}",
                    )

                    if upload_uri_cis:
                        results["cis"] = {
                            "upload": True,
                            "path": upload_uri_cis,
                        }
                        logger.info(
                            "CIS report %s uploaded to %s",
                            latest_cis,
                            upload_uri_cis,
                        )
                    else:
                        results["cis"] = {"upload": False, "path": out_dir}
                        logger.warning(
                            "CIS report %s saved locally at %s",
                            latest_cis,
                            out_dir,
                        )

                except Exception as e:
                    logger.error("Error generating CIS report %s: %s", latest_cis, e)
                    results["cis"] = {
                        "upload": False,
                        "path": "",
                        "error": str(e),
                    }
                finally:
                    # Free ReportLab/matplotlib memory before moving on.
                    gc.collect()

    # Clean up temporary files only if every requested report has been
    # successfully uploaded. All result entries now share the same flat
    # shape, so the check is a single comprehension.
    upload_flags = [
        bool(entry.get("upload", False))
        for entry in results.values()
        if isinstance(entry, dict) and entry.get("upload") is not None
    ]
    all_uploaded = bool(upload_flags) and all(upload_flags)

    if all_uploaded:
        try:
            rmtree(Path(out_dir), ignore_errors=True)
            logger.info("Cleaned up temporary files at %s", out_dir)
        except Exception as e:
            logger.error("Error deleting output files: %s", e)

    logger.info("Compliance reports generation completed. Results: %s", results)
    return results


def generate_compliance_reports_job(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    generate_threatscore: bool = True,
    generate_ens: bool = True,
    generate_nis2: bool = True,
    generate_csa: bool = True,
    generate_cis: bool = True,
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
        generate_csa: Whether to generate CSA CCM report.
        generate_cis: Whether to generate the CIS Benchmark report for the
            latest CIS version available for the provider.

    Returns:
        Dictionary with results for each report type. Every entry shares the
        same flat ``{"upload", "path", "error"?}`` shape.
    """
    return generate_compliance_reports(
        tenant_id=tenant_id,
        scan_id=scan_id,
        provider_id=provider_id,
        generate_threatscore=generate_threatscore,
        generate_ens=generate_ens,
        generate_nis2=generate_nis2,
        generate_csa=generate_csa,
        generate_cis=generate_cis,
    )
