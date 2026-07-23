from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.configuration.configuration_client import (
    configuration_client,
)


class configuration_remote_login_passwordfile_secure(Check):
    """Check that the password file is not shared between databases."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A single report for the audited database, or none when the
            initialization parameters could not be read.
        """
        findings = []
        if not configuration_client.parameters:
            return findings
        report = CheckReportOracledb(
            metadata=self.metadata(),
            resource={},
            resource_name="remote_login_passwordfile",
            resource_id=f"{configuration_client.database_name}/remote_login_passwordfile",
        )
        value = (
            configuration_client.parameters.get("remote_login_passwordfile") or ""
        ).upper()
        if value in ("EXCLUSIVE", "NONE"):
            report.status = "PASS"
            report.status_extended = f"Database {configuration_client.database_name} uses a dedicated password file (REMOTE_LOGIN_PASSWORDFILE={value})."
        else:
            report.status = "FAIL"
            report.status_extended = f"Database {configuration_client.database_name} shares its password file with other databases (REMOTE_LOGIN_PASSWORDFILE={value})."
        findings.append(report)
        return findings
