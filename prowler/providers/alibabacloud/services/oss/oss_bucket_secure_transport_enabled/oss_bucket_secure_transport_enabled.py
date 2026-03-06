from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.oss.oss_client import oss_client


def _is_secure_transport_enforced(policy_document: dict) -> bool:
    """
    Check if a bucket policy enforces secure transport (HTTPS only).

    A policy enforces secure transport if it has:
    - "Condition": {"Bool": {"acs:SecureTransport": ["true"]}} with "Effect": "Allow"
    OR
    - "Condition": {"Bool": {"acs:SecureTransport": ["false"]}} with "Effect": "Deny"

    Args:
        policy_document: The parsed policy document as a dictionary.

    Returns:
        bool: True if secure transport is enforced, False otherwise.
    """
    if not policy_document:
        return False

    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect", "")
        condition = statement.get("Condition", {})

        if not condition:
            continue

        # Check for SecureTransport condition
        bool_condition = condition.get("Bool", {})
        secure_transport = bool_condition.get("acs:SecureTransport", [])

        if secure_transport:
            # Check if it's a list or single value
            if isinstance(secure_transport, list):
                secure_transport_value = (
                    secure_transport[0] if secure_transport else None
                )
            else:
                secure_transport_value = secure_transport

            # Secure transport is enforced if:
            # 1. Effect: Allow with SecureTransport: true (only HTTPS allowed)
            # 2. Effect: Deny with SecureTransport: false (HTTP denied)
            if effect == "Allow" and secure_transport_value == "true":
                return True
            elif effect == "Deny" and secure_transport_value == "false":
                return True

    return False


class oss_bucket_secure_transport_enabled(Check):
    """Check if 'Secure transfer required' is set to 'Enabled' for OSS buckets."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for bucket in oss_client.buckets.values():
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = bucket.arn

            # Check if secure transport is enforced via bucket policy
            secure_transport_enforced = _is_secure_transport_enforced(bucket.policy)

            if secure_transport_enforced:
                report.status = "PASS"
                report.status_extended = (
                    f"OSS bucket {bucket.name} has secure transfer required enabled."
                )
            else:
                report.status = "FAIL"
                if bucket.policy:
                    report.status_extended = f"OSS bucket {bucket.name} does not have secure transfer required enabled."
                else:
                    report.status_extended = f"OSS bucket {bucket.name} does not have secure transfer required enabled."

            findings.append(report)

        return findings
