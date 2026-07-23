from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.users.users_client import users_client


class users_failed_login_attempts_limited(Check):
    """Check that database users lock after a limited number of failed login attempts."""

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
            if user.failed_login_attempts == "UNLIMITED":
                report.status = "FAIL"
                report.status_extended = f"User {user.name} allows unlimited failed login attempts (profile {user.profile})."
            else:
                report.status = "PASS"
                report.status_extended = f"User {user.name} locks after {user.failed_login_attempts} failed login attempts (profile {user.profile})."
            findings.append(report)
        return findings
