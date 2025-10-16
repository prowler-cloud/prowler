"""Check if no resources are created in the root compartment."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_no_resources_in_root_compartment(Check):
    """Check if no resources are created in the root compartment."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_no_resources_in_root_compartment check."""
        findings = []

        # Get the root compartment ID (tenancy OCID)
        root_compartment_id = identity_client.audited_tenancy

        # Get resources found in root compartment via search
        resources_in_root = identity_client.root_compartment_resources
        resource_count = len(resources_in_root)

        # Create finding
        report = Check_Report_OCI(
            metadata=self.metadata(),
            resource={},
            region=identity_client.provider.identity.region,
            resource_name="Root Compartment Resources",
            resource_id=root_compartment_id,
            compartment_id=root_compartment_id,
        )

        if resource_count == 0:
            report.status = "PASS"
            report.status_extended = "No resources found in the root compartment."
        else:
            report.status = "FAIL"
            # Get resource type summary
            resource_types = {}
            for resource in resources_in_root:
                resource_type = resource.resource_type
                resource_types[resource_type] = resource_types.get(resource_type, 0) + 1

            resource_summary = ", ".join(
                [f"{count} {rtype}(s)" for rtype, count in resource_types.items()]
            )
            report.status_extended = f"Found {resource_count} resource(s) in root compartment: {resource_summary}."

        findings.append(report)

        return findings
