"""Check Ensure customer created Customer Managed Key (CMK) is rotated at least annually."""

from datetime import datetime, timedelta, timezone

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

            now = datetime.now(timezone.utc)
            max_age = timedelta(days=365)

            manually_rotated_recently = (
                key.current_key_version_time_created is not None
                and (now - key.current_key_version_time_created) <= max_age
            )

            if (
                key.is_auto_rotation_enabled
                or (
                    key.rotation_interval_in_days is not None
                    and key.rotation_interval_in_days <= 365
                )
                or manually_rotated_recently
            ):
                report.status = "PASS"
                if key.is_auto_rotation_enabled:
                    report.status_extended = f"KMS key {key.name} has auto-rotation enabled with interval of {key.rotation_interval_in_days} days."
                elif manually_rotated_recently:
                    report.status_extended = f"KMS key {key.name} was manually rotated within the last 365 days."
                else:
                    report.status_extended = f"KMS key {key.name} has rotation interval set to {key.rotation_interval_in_days} days."
            else:
                report.status = "FAIL"
                report.status_extended = f"KMS key {key.name} has not been rotated within the last 365 days and does not have auto-rotation enabled."

            findings.append(report)

        return findings
