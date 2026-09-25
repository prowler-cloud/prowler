from typing import Any

from prowler.lib.check.models import Check_Report_AWS


def get_kms_inventory_error_reports(
    metadata: dict, kms_client_ref: Any
) -> list[Check_Report_AWS]:
    """Build findings for regions with an incomplete key inventory.

    Args:
        metadata: Metadata for the check emitting the findings.
        kms_client_ref: KMS service instance containing regional scan errors.

    Returns:
        One MANUAL finding for each region whose keys could not be listed.
    """
    findings = []
    scan_errors = getattr(kms_client_ref, "keys_scan_errors", {})
    if not isinstance(scan_errors, dict):
        return findings

    for region, error in sorted(scan_errors.items()):
        report = Check_Report_AWS(metadata=metadata, resource={"region": region})
        report.region = region
        report.resource_id = "key/unknown"
        report.resource_arn = (
            f"arn:{kms_client_ref.audited_partition}:kms:{region}:"
            f"{kms_client_ref.audited_account}:key/unknown"
        )
        report.status = "MANUAL"
        report.status_extended = (
            f"KMS keys could not be listed in region {region} ({error}); "
            f"KMS resources in this region could not be evaluated and must "
            f"be verified manually."
        )
        findings.append(report)

    return findings


def get_kms_key_detail_error_report(metadata: dict, key: Any) -> Check_Report_AWS:
    """Build a finding for a key whose metadata could not be retrieved.

    Args:
        metadata: Metadata for the check emitting the finding.
        key: KMS key whose DescribeKey call failed.

    Returns:
        A MANUAL finding for the incomplete key.
    """
    error = getattr(key, "detail_fetch_error", None) or "UnknownError"
    report = Check_Report_AWS(metadata=metadata, resource=key)
    report.status = "MANUAL"
    report.status_extended = (
        f"KMS key {key.id} could not be described in region {key.region} "
        f"({error}); its configuration could not be evaluated and must be "
        f"verified manually."
    )
    return report
