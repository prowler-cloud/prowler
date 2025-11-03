"""Check Ensure customer created Customer Managed Key (CMK) is rotated at least annually."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.kms.kms_client import kms_client


class kms_key_rotation_enabled(Check):
    """Check Ensure customer created Customer Managed Key (CMK) is rotated at least annually."""

    def execute(self) -> Check_Report_OCI:
        """Execute the kms_key_rotation_enabled check."""
        findings = []

        for key in kms_client.keys:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=key,
                region=key.region,
                resource_name=key.name,
                resource_id=key.id,
                compartment_id=key.compartment_id,
            )

            # Check if auto-rotation is enabled OR if rotation interval is set and <= 365 days
            if key.is_auto_rotation_enabled or (
                key.rotation_interval_in_days is not None
                and key.rotation_interval_in_days <= 365
            ):
                report.status = "PASS"
                report.status_extended = f"KMS key '{key.name}' has rotation enabled (auto-rotation: {key.is_auto_rotation_enabled}, interval: {key.rotation_interval_in_days} days)."
            else:
                report.status = "FAIL"
                report.status_extended = f"KMS key '{key.name}' does not have rotation enabled or rotation interval exceeds 365 days."

            findings.append(report)

        return findings
