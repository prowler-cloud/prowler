"""Check Ensure all OCI IAM user accounts have a valid and current email address."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_user_valid_email_address(Check):
    """Check Ensure all OCI IAM user accounts have a valid and current email address."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_valid_email_address check."""
        findings = []

        # Check users have valid email
        for user in identity_client.users:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=user,
                region=user.region,
                resource_name=user.name,
                resource_id=user.id,
                compartment_id=user.compartment_id,
            )

            if user.email and "@" in user.email:
                report.status = "PASS"
                report.status_extended = f"User {user.name} has a valid email address."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} does not have a valid email address."
                )

            findings.append(report)

        return findings
