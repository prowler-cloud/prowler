from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.configuration.configuration_client import (
    configuration_client,
)


class configuration_sec_return_server_release_banner_disabled(Check):
    """Check that the server release banner is not returned to clients."""

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
            resource_name="sec_return_server_release_banner",
            resource_id=f"{configuration_client.database_name}/sec_return_server_release_banner",
        )
        value = (
            configuration_client.parameters.get("sec_return_server_release_banner")
            or ""
        ).upper()
        if value != "TRUE":
            report.status = "PASS"
            report.status_extended = f"Database {configuration_client.database_name} does not return the full release banner to unauthenticated clients (SEC_RETURN_SERVER_RELEASE_BANNER=FALSE)."
        else:
            report.status = "FAIL"
            report.status_extended = f"Database {configuration_client.database_name} returns the full release banner to unauthenticated clients (SEC_RETURN_SERVER_RELEASE_BANNER=TRUE)."
        findings.append(report)
        return findings
