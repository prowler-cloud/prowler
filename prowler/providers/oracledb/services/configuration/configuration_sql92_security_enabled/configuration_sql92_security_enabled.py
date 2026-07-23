from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.configuration.configuration_client import (
    configuration_client,
)


class configuration_sql92_security_enabled(Check):
    """Check that SQL92 security is enabled for UPDATE/DELETE statements."""

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
            resource_name="sql92_security",
            resource_id=f"{configuration_client.database_name}/sql92_security",
        )
        value = (configuration_client.parameters.get("sql92_security") or "").upper()
        if value == "TRUE":
            report.status = "PASS"
            report.status_extended = f"Database {configuration_client.database_name} requires SELECT privilege on columns referenced by conditional UPDATE/DELETE statements (SQL92_SECURITY=TRUE)."
        else:
            report.status = "FAIL"
            report.status_extended = f"Database {configuration_client.database_name} allows data inference through conditional UPDATE/DELETE statements (SQL92_SECURITY=FALSE)."
        findings.append(report)
        return findings
