from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.privileges.privileges_client import (
    privileges_client,
)


class privileges_public_no_system_privileges(Check):
    """Check that no system privileges are granted to PUBLIC."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A single report for the audited database.
        """
        findings = []
        report = CheckReportOracledb(
            metadata=self.metadata(),
            resource={},
            resource_name=privileges_client.database_name,
            resource_id=privileges_client.database_name,
        )
        public_privileges = privileges_client.public_system_privileges
        if public_privileges:
            report.status = "FAIL"
            report.status_extended = (
                f"Database {privileges_client.database_name} grants system "
                f"privileges to PUBLIC: {', '.join(public_privileges)}."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"Database {privileges_client.database_name} does not grant "
                "any system privilege to PUBLIC."
            )
        findings.append(report)
        return findings
