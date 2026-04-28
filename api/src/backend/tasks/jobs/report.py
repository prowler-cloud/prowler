import gc
import os
import re
import time
from collections.abc import Iterable
from pathlib import Path
from shutil import rmtree
from uuid import UUID

import fcntl
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

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import rls_transaction
from api.models import Provider, Scan, ScanSummary, StateChoices, ThreatScoreSnapshot
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput

logger = get_task_logger(__name__)
STALE_TMP_OUTPUT_MAX_AGE_HOURS = 48
STALE_TMP_OUTPUT_MAX_DELETIONS_PER_RUN = 50
STALE_TMP_OUTPUT_THROTTLE_SECONDS = 60 * 60
STALE_TMP_OUTPUT_LOCK_FILE_NAME = ".stale_tmp_cleanup.lock"

# Refuse to ever run rmtree against shared system roots; the configured
# DJANGO_TMP_OUTPUT_DIRECTORY must be a dedicated subdirectory.
_FORBIDDEN_CLEANUP_ROOTS = frozenset(
    Path(p).resolve()
    for p in ("/", "/tmp", "/var", "/var/tmp", "/home", "/root", "/etc", "/usr")
)


def _resolve_stale_tmp_safe_root() -> Path | None:
    """Resolve the configured tmp output directory, rejecting unsafe roots."""
    try:
        configured_root = Path(DJANGO_TMP_OUTPUT_DIRECTORY).resolve()
    except OSError:
        return None
    if configured_root in _FORBIDDEN_CLEANUP_ROOTS:
        return None
    return configured_root


STALE_TMP_OUTPUT_SAFE_ROOT = _resolve_stale_tmp_safe_root()

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


def _should_run_stale_cleanup(
    root_path: Path,
    throttle_seconds: int = STALE_TMP_OUTPUT_THROTTLE_SECONDS,
) -> bool:
    """Throttle stale cleanup to at most once per hour per host."""
    lock_file_path = root_path / STALE_TMP_OUTPUT_LOCK_FILE_NAME
    now_timestamp = int(time.time())

    try:
        with lock_file_path.open("a+", encoding="ascii") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            lock_file.seek(0)
            previous_value = lock_file.read().strip()
            try:
                last_run_timestamp = int(previous_value) if previous_value else 0
            except ValueError:
                last_run_timestamp = 0

            if now_timestamp - last_run_timestamp < throttle_seconds:
                return False

            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(str(now_timestamp))
            lock_file.flush()
            os.fsync(lock_file.fileno())
    except OSError as error:
        logger.warning("Skipping stale tmp cleanup: lock file error (%s)", error)
        return False

    return True


def _is_scan_metadata_protected(
    scan_path: Path,
    scan_state: str | None,
    output_location: str | None,
) -> bool:
    """
    Return True when metadata indicates the directory must not be deleted.

    Protected cases:
    - Scan is still EXECUTING.
    - Scan has a local output artifact path (non-S3) under this scan directory.
    """
    if scan_state == StateChoices.EXECUTING.value:
        return True

    output_location = output_location or ""
    if output_location and not output_location.startswith("s3://"):
        try:
            resolved_output_location = Path(output_location).resolve()
        except OSError:
            # Conservative fallback: if we cannot resolve a local output path,
            # keep the directory to avoid deleting potentially needed artifacts.
            return True

        if (
            resolved_output_location == scan_path
            or scan_path in resolved_output_location.parents
        ):
            return True

    return False


def _is_scan_directory_protected(
    tenant_id: str,
    scan_id: str,
    scan_path: Path,
) -> bool:
    """
    DB-backed wrapper used when batch metadata is not already available.
    """
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        return False

    try:
        scan = (
            Scan.all_objects.using(MainRouter.admin_db)
            .filter(tenant_id=tenant_id, id=scan_uuid)
            .only("state", "output_location")
            .first()
        )
    except Exception as error:
        logger.warning(
            "Skipping stale tmp cleanup for %s/%s due to scan lookup error: %s",
            tenant_id,
            scan_id,
            error,
        )
        return True

    if not scan:
        return False

    return _is_scan_metadata_protected(
        scan_path=scan_path,
        scan_state=scan.state,
        output_location=scan.output_location,
    )


def _cleanup_stale_tmp_output_directories(
    tmp_output_root: str,
    max_age_hours: int = STALE_TMP_OUTPUT_MAX_AGE_HOURS,
    exclude_scan: tuple[str, str] | None = None,
    max_deletions_per_run: int = STALE_TMP_OUTPUT_MAX_DELETIONS_PER_RUN,
) -> int:
    """
    Opportunistically delete stale scan directories under the tmp output root.

    Expected directory layout:
        <tmp_output_root>/<tenant_id>/<scan_id>/...

    Each run that wins the per-host throttle sweeps every tenant directory so
    leftover artifacts cannot pile up for tenants whose own tasks happen to
    lose the throttle race.

    Args:
        tmp_output_root: Base tmp output path.
        max_age_hours: Directory max age before deletion.
        exclude_scan: Optional (tenant_id, scan_id) that must never be deleted.
        max_deletions_per_run: Max number of scan directories deleted per run.

    Returns:
        Number of deleted scan directories.
    """
    try:
        if max_age_hours <= 0:
            return 0

        try:
            root_path = Path(tmp_output_root).resolve()
        except OSError as error:
            logger.warning(
                "Skipping stale tmp cleanup: unable to resolve %s (%s)",
                tmp_output_root,
                error,
            )
            return 0

        if (
            STALE_TMP_OUTPUT_SAFE_ROOT is None
            or root_path != STALE_TMP_OUTPUT_SAFE_ROOT
        ):
            logger.warning(
                "Skipping stale tmp cleanup: unsupported root %s (allowed: %s)",
                root_path,
                STALE_TMP_OUTPUT_SAFE_ROOT,
            )
            return 0

        if not root_path.exists() or not root_path.is_dir():
            return 0

        if max_deletions_per_run <= 0:
            return 0

        if not _should_run_stale_cleanup(root_path):
            return 0

        cutoff_timestamp = time.time() - (max_age_hours * 60 * 60)
        deleted_scan_dirs = 0

        try:
            tenant_dirs = list(root_path.iterdir())
        except OSError as error:
            logger.warning(
                "Skipping stale tmp cleanup: unable to list %s (%s)",
                root_path,
                error,
            )
            return 0

        for tenant_dir in tenant_dirs:
            if deleted_scan_dirs >= max_deletions_per_run:
                break

            if not tenant_dir.is_dir() or tenant_dir.is_symlink():
                continue

            try:
                scan_dirs = list(tenant_dir.iterdir())
            except OSError:
                continue

            stale_candidates: list[tuple[str, Path, UUID | None]] = []
            for scan_dir in scan_dirs:
                if not scan_dir.is_dir() or scan_dir.is_symlink():
                    continue

                if exclude_scan and (
                    tenant_dir.name == exclude_scan[0]
                    and scan_dir.name == exclude_scan[1]
                ):
                    continue

                try:
                    if scan_dir.stat().st_mtime >= cutoff_timestamp:
                        continue
                except OSError:
                    continue

                try:
                    resolved_scan_dir = scan_dir.resolve()
                except OSError:
                    continue

                if root_path not in resolved_scan_dir.parents:
                    logger.warning(
                        "Skipping stale tmp cleanup for path outside root: %s",
                        resolved_scan_dir,
                    )
                    continue

                try:
                    scan_uuid: UUID | None = UUID(scan_dir.name)
                except ValueError:
                    scan_uuid = None

                stale_candidates.append((scan_dir.name, resolved_scan_dir, scan_uuid))

            if not stale_candidates:
                continue

            scan_metadata_by_id: dict[UUID, tuple[str | None, str | None]] = {}
            metadata_preload_succeeded = False
            candidate_scan_ids = [
                candidate[2] for candidate in stale_candidates if candidate[2]
            ]
            if candidate_scan_ids:
                try:
                    scan_rows = (
                        Scan.all_objects.using(MainRouter.admin_db)
                        .filter(
                            tenant_id=tenant_dir.name,
                            id__in=candidate_scan_ids,
                        )
                        .values_list("id", "state", "output_location")
                    )
                    scan_metadata_by_id = {
                        scan_id: (scan_state, output_location)
                        for scan_id, scan_state, output_location in scan_rows
                    }
                    metadata_preload_succeeded = True
                except Exception as error:
                    logger.warning(
                        "Skipping stale tmp cleanup metadata preload for tenant %s: %s",
                        tenant_dir.name,
                        error,
                    )
            else:
                metadata_preload_succeeded = True

            for scan_name, resolved_scan_dir, scan_uuid in stale_candidates:
                if deleted_scan_dirs >= max_deletions_per_run:
                    break

                should_check_scan_fallback = True
                if scan_uuid and metadata_preload_succeeded:
                    should_check_scan_fallback = False
                    scan_metadata = scan_metadata_by_id.get(scan_uuid)
                    if scan_metadata:
                        scan_state, output_location = scan_metadata
                        if _is_scan_metadata_protected(
                            scan_path=resolved_scan_dir,
                            scan_state=scan_state,
                            output_location=output_location,
                        ):
                            continue

                if should_check_scan_fallback and _is_scan_directory_protected(
                    tenant_id=tenant_dir.name,
                    scan_id=scan_name,
                    scan_path=resolved_scan_dir,
                ):
                    continue

                try:
                    rmtree(resolved_scan_dir, ignore_errors=True)
                    deleted_scan_dirs += 1
                except Exception as error:
                    logger.warning(
                        "Error cleaning stale tmp directory %s: %s",
                        resolved_scan_dir,
                        error,
                    )

        if deleted_scan_dirs:
            logger.info(
                "Deleted %s stale tmp output directories older than %sh from %s",
                deleted_scan_dirs,
                max_age_hours,
                root_path,
            )
        if deleted_scan_dirs >= max_deletions_per_run:
            logger.info(
                "Stale tmp cleanup hit deletion limit (%s) for root %s",
                max_deletions_per_run,
                root_path,
            )

        return deleted_scan_dirs
    except Exception as error:
        logger.warning(
            "Skipping stale tmp cleanup due to unexpected error: %s",
            error,
            exc_info=True,
        )
        return 0


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

    try:
        _cleanup_stale_tmp_output_directories(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            max_age_hours=STALE_TMP_OUTPUT_MAX_AGE_HOURS,
            exclude_scan=(tenant_id, scan_id),
        )
    except Exception as error:
        logger.warning(
            "Skipping stale tmp cleanup before compliance reports for scan %s: %s",
            scan_id,
            error,
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
    # (that list drifts the moment a new CIS JSON ships). Instead, we inspect
    # the dynamically loaded framework map and pick the latest available CIS
    # version, if any.
    latest_cis: str | None = None
    if generate_cis:
        try:
            frameworks_bulk = Compliance.get_bulk(provider_type)
            latest_cis = _pick_latest_cis_variant(
                name for name in frameworks_bulk.keys() if name.startswith("cis_")
            )
        except Exception as e:
            logger.error("Error discovering CIS variants for %s: %s", provider_type, e)
            results["cis"] = {"upload": False, "path": "", "error": str(e)}
            generate_cis = False
        else:
            if latest_cis is None:
                logger.info("No CIS variants available for provider %s", provider_type)
                results["cis"] = {"upload": False, "path": ""}
                generate_cis = False
            else:
                logger.info(
                    "Selected latest CIS variant for provider %s: %s",
                    provider_type,
                    latest_cis,
                )

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

    generated_report_keys: list[str] = []
    output_paths: dict[str, str] = {}
    out_dir: str | None = None

    # Generate output directories only for enabled and supported report types.
    try:
        logger.info("Generating output directories")
        if generate_threatscore:
            output_paths["threatscore"] = _generate_compliance_output_directory(
                DJANGO_TMP_OUTPUT_DIRECTORY,
                provider_uid,
                tenant_id,
                scan_id,
                compliance_framework="threatscore",
            )
        if generate_ens:
            output_paths["ens"] = _generate_compliance_output_directory(
                DJANGO_TMP_OUTPUT_DIRECTORY,
                provider_uid,
                tenant_id,
                scan_id,
                compliance_framework="ens",
            )
        if generate_nis2:
            output_paths["nis2"] = _generate_compliance_output_directory(
                DJANGO_TMP_OUTPUT_DIRECTORY,
                provider_uid,
                tenant_id,
                scan_id,
                compliance_framework="nis2",
            )
        if generate_csa:
            output_paths["csa"] = _generate_compliance_output_directory(
                DJANGO_TMP_OUTPUT_DIRECTORY,
                provider_uid,
                tenant_id,
                scan_id,
                compliance_framework="csa",
            )
        if generate_cis and latest_cis:
            output_paths["cis"] = _generate_compliance_output_directory(
                DJANGO_TMP_OUTPUT_DIRECTORY,
                provider_uid,
                tenant_id,
                scan_id,
                compliance_framework="cis",
            )
        if output_paths:
            first_output_path = next(iter(output_paths.values()))
            out_dir = str(Path(first_output_path).parent.parent)
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
        generated_report_keys.append("threatscore")
        threatscore_path = output_paths["threatscore"]
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
        generated_report_keys.append("ens")
        ens_path = output_paths["ens"]
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
        generated_report_keys.append("nis2")
        nis2_path = output_paths["nis2"]
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
        generated_report_keys.append("csa")
        csa_path = output_paths["csa"]
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
    # time rather than hard-coding a per-provider mapping.
    if generate_cis and latest_cis:
        generated_report_keys.append("cis")
        cis_path = output_paths["cis"]
        if out_dir is None:
            out_dir = str(Path(cis_path).parent.parent)
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

    # Clean up temporary files only if all generated reports were
    # uploaded successfully. Reports skipped for provider incompatibility
    # or missing CIS variants must not block cleanup.
    all_uploaded = bool(generated_report_keys) and all(
        results.get(report_key, {}).get("upload", False)
        for report_key in generated_report_keys
    )

    if all_uploaded and out_dir:
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
