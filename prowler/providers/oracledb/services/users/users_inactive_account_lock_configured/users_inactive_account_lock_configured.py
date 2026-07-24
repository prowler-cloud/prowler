from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.users.users_client import users_client


class users_inactive_account_lock_configured(Check):
    """Check that database users are locked after a period of inactivity."""

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
            if user.inactive_account_time in (None, "UNLIMITED"):
                report.status = "FAIL"
                report.status_extended = f"User {user.name} is never locked for inactivity (profile {user.profile})."
            else:
                report.status = "PASS"
                report.status_extended = f"User {user.name} is locked after {user.inactive_account_time} days of inactivity (profile {user.profile})."
            findings.append(report)
        return findings
