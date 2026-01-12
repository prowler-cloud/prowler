"""Check if at least one non-root compartment exists in the tenancy."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_non_root_compartment_exists(Check):
    """Check if at least one non-root compartment exists in the tenancy."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_non_root_compartment_exists check."""
        findings = []

        # Get active non-root compartments from search
        active_compartments = identity_client.active_non_root_compartments
        compartment_count = len(active_compartments)

        # Create a single finding for the tenancy
        report = Check_Report_OCI(
            metadata=self.metadata(),
            resource={},
            region=identity_client.provider.identity.region,
            resource_name="Tenancy Compartments",
            resource_id=identity_client.audited_tenancy,
            compartment_id=identity_client.audited_tenancy,
        )

        if compartment_count > 0:
            report.status = "PASS"
            report.status_extended = f"Tenancy has {compartment_count} active non-root compartment(s) created for organizing cloud resources."
        else:
            report.status = "FAIL"
            report.status_extended = "Tenancy has no active non-root compartments created. At least one non-root compartment should be created to organize cloud resources."

        findings.append(report)

        return findings
