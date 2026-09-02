from prowler.lib.check.models import Check_Report_AWS


def generate_scan_error_reports(
    metadata,
    action_text: str,
    client=None,
    keys_scan_errors: dict | None = None,
) -> list[Check_Report_AWS]:
    """Generate MANUAL findings for regions where KMS keys could not be listed.

    Args:
        metadata: Check metadata.
        action_text: The manual verification instruction text.
        client: Optional KMS client instance. Defaults to kms_client.
        keys_scan_errors: Optional mapping of region to scan error code.
            Defaults to client.keys_scan_errors.

    Returns:
        list[Check_Report_AWS]: List of MANUAL report findings for regional scan errors.
    """
    if client is None:
        from prowler.providers.aws.services.kms.kms_client import kms_client

        client = kms_client
    if keys_scan_errors is None:
        keys_scan_errors = getattr(client, "keys_scan_errors", {})

    findings = []
    for region, error in sorted(keys_scan_errors.items()):
        report = Check_Report_AWS(metadata=metadata, resource={"region": region})
        report.region = region
        report.resource_id = "key/unknown"
        audited_partition = getattr(client, "audited_partition", "aws")
        audited_account = getattr(client, "audited_account", "")
        report.resource_arn = (
            f"arn:{audited_partition}:kms:{region}:" f"{audited_account}:key/unknown"
        )
        report.status = "MANUAL"
        report.status_extended = (
            f"KMS keys could not be listed in region {region} ({error}); "
            f"verify manually that {action_text}."
        )
        findings.append(report)
    return findings


def is_key_detail_unretrieved(key) -> bool:
    """Return True if a KMS key's details could not be retrieved.

    Args:
        key: The KMS Key model object or mock.

    Returns:
        bool: True if key details could not be retrieved, False otherwise.
    """
    if getattr(key, "detail_retrieved", True) is False:
        return True
    describe_error = getattr(key, "describe_error", None)
    if isinstance(describe_error, str) and describe_error:
        return True
    return False


def generate_describe_error_report(
    metadata,
    key,
    action_text: str,
) -> Check_Report_AWS:
    """Generate a MANUAL finding for a key whose details could not be retrieved.

    Args:
        metadata: Check metadata.
        key: The KMS Key model object.
        action_text: The manual verification instruction text.

    Returns:
        Check_Report_AWS: MANUAL report for the unretrieved key.
    """
    error = getattr(key, "describe_error", None)
    if not isinstance(error, str) or not error:
        error = "DescribeKey failed"
    report = Check_Report_AWS(metadata=metadata, resource=key)
    report.status = "MANUAL"
    report.status_extended = (
        f"KMS key {key.id} details could not be retrieved ({error}); "
        f"verify manually that {action_text}."
    )
    return report
