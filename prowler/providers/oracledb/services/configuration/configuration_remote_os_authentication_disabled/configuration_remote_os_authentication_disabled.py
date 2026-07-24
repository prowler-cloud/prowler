from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.configuration.configuration_client import (
    configuration_client,
)


class configuration_remote_os_authentication_disabled(Check):
    """Check that remote operating system authentication is disabled."""

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
            resource_name="remote_os_authent",
            resource_id=f"{configuration_client.database_name}/remote_os_authent",
        )
        value = (configuration_client.parameters.get("remote_os_authent") or "").upper()
        if value != "TRUE":
            report.status = "PASS"
            report.status_extended = f"Database {configuration_client.database_name} does not trust client operating system authentication (REMOTE_OS_AUTHENT=FALSE)."
        else:
            report.status = "FAIL"
            report.status_extended = f"Database {configuration_client.database_name} trusts client operating system authentication (REMOTE_OS_AUTHENT=TRUE)."
        findings.append(report)
        return findings
