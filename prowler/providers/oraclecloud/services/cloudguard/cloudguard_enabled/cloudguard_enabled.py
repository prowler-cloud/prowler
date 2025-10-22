"""Check Ensure Cloud Guard is enabled in the root compartment of the tenancy."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.cloudguard.cloudguard_client import (
    cloudguard_client,
)


class cloudguard_enabled(Check):
    """Check Ensure Cloud Guard is enabled in the root compartment of the tenancy."""

    def execute(self) -> Check_Report_OCI:
        """Execute the cloudguard_enabled check."""
        findings = []

        report = Check_Report_OCI(
            metadata=self.metadata(),
            resource=cloudguard_client.configuration,
            region="global",
            resource_name="Cloud Guard",
            resource_id=cloudguard_client.audited_tenancy,
            compartment_id=cloudguard_client.audited_tenancy,
        )

        if (
            cloudguard_client.configuration
            and cloudguard_client.configuration.status == "ENABLED"
        ):
            report.status = "PASS"
            report.status_extended = "Cloud Guard is enabled in the root compartment."
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Cloud Guard is not enabled in the root compartment."
            )

        findings.append(report)

        return findings
