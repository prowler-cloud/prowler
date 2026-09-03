from prowler.lib.check.models import Check, CheckReportSnowflake
from prowler.providers.snowflake.services.users.users_client import users_client


class users_mfa_enabled(Check):
    """Check that users who can sign in with a password are protected by MFA."""

    def execute(self) -> list[CheckReportSnowflake]:
        """Execute the users_mfa_enabled check.

        Only users who can actually authenticate with a password are evaluated. A
        disabled user cannot sign in, and a user without a password authenticates by
        key pair, so neither is exposed by the absence of MFA and neither is reported.

        Returns:
            list[CheckReportSnowflake]: One finding per user that can use password
            authentication.
        """
        findings = []

        for user in users_client.users:
            if user.disabled or not user.has_password:
                continue

            report = CheckReportSnowflake(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.name,
            )

            if not user.mfa_enrolled:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} can sign in with a password and is not enrolled "
                    "in MFA."
                )
            elif user.mfa_bypassed:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} is enrolled in MFA but has an active bypass "
                    f"until {user.bypass_mfa_until}, so a password alone is currently "
                    "sufficient."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"User {user.name} is enrolled in MFA."

            findings.append(report)

        return findings
