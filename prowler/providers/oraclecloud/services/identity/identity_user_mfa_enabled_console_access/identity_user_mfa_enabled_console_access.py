"""Check if MFA is enabled for all users with console password."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_user_mfa_enabled_console_access(Check):
    """Check if MFA is enabled for all users with console password."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_user_mfa_enabled_console_access check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        for user in identity_client.users:
            # Only check users with console access
            if user.can_use_console_password:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=user,
                    region=user.region,
                    resource_name=user.name,
                    resource_id=user.id,
                    compartment_id=user.compartment_id,
                )

                if user.is_mfa_activated:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User {user.name} has MFA enabled for console access."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = f"User {user.name} has console password enabled but MFA is not activated."

                findings.append(report)

        return findings
