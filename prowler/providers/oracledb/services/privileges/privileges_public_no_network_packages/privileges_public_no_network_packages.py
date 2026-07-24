from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.privileges.privileges_client import (
    privileges_client,
)
from prowler.providers.oracledb.services.privileges.privileges_service import (
    NETWORK_PACKAGES,
)


class privileges_public_no_network_packages(Check):
    """Check that network PL/SQL packages are not executable by PUBLIC."""

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
        exposed_packages = sorted(
            set(privileges_client.public_execute_packages) & NETWORK_PACKAGES
        )
        if exposed_packages:
            report.status = "FAIL"
            report.status_extended = (
                f"Database {privileges_client.database_name} grants PUBLIC "
                f"execute on network packages: "
                f"{', '.join(exposed_packages)}."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"Database {privileges_client.database_name} does not grant "
                f"PUBLIC execute on any network package."
            )
        findings.append(report)
        return findings
