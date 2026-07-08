from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.users.users_client import users_client


class users_password_expiration_configured(Check):
    """Check that database users have a limited password lifetime."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A list of reports, one per non-Oracle-maintained user.
        """
        findings = []
        for user in users_client.users:
            if user.oracle_maintained:
                continue
            report = CheckReportOracledb(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.name,
            )
            if user.password_life_time == "UNLIMITED":
                report.status = "FAIL"
                report.status_extended = f"User {user.name} has an unlimited password lifetime (profile {user.profile})."
            else:
                report.status = "PASS"
                report.status_extended = f"User {user.name} has a password lifetime of {user.password_life_time} days (profile {user.profile})."
            findings.append(report)
        return findings
