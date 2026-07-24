from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.configuration.configuration_client import (
    configuration_client,
)


class configuration_dictionary_accessibility_disabled(Check):
    """Check that access to data dictionary objects is restricted."""

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
            resource_name="o7_dictionary_accessibility",
            resource_id=f"{configuration_client.database_name}/o7_dictionary_accessibility",
        )
        value = (
            configuration_client.parameters.get("o7_dictionary_accessibility") or ""
        ).upper()
        if value != "TRUE":
            report.status = "PASS"
            report.status_extended = f"Database {configuration_client.database_name} restricts access to data dictionary objects (O7_DICTIONARY_ACCESSIBILITY=FALSE)."
        else:
            report.status = "FAIL"
            report.status_extended = f"Database {configuration_client.database_name} allows ANY-style privileges on data dictionary objects (O7_DICTIONARY_ACCESSIBILITY=TRUE)."
        findings.append(report)
        return findings
