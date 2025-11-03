"""Check Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_instance_principal_used(Check):
    """Check Ensure Instance Principal authentication is used for OCI instances, OCI Cloud Databases and OCI Functions to access OCI resources."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_instance_principal_used check."""
        findings = []

        # Resources to check for in matching rules
        oci_resources = [
            "fnfunc",
            "instance",
            "autonomousdatabase",
            "resource.compartment.id",
        ]

        # Track which dynamic groups have valid instance principal configurations
        valid_dynamic_groups = []
        invalid_dynamic_groups = []

        for dynamic_group in identity_client.dynamic_groups:
            matching_rule_upper = dynamic_group.matching_rule.upper()

            # Check if any of the OCI resources are in the matching rule
            if any(
                oci_resource.upper() in matching_rule_upper
                for oci_resource in oci_resources
            ):
                valid_dynamic_groups.append(dynamic_group)
            else:
                invalid_dynamic_groups.append(dynamic_group)

        # Determine the region - use the first dynamic group's region if available, otherwise first audited region
        region = "global"
        if identity_client.dynamic_groups:
            region = identity_client.dynamic_groups[0].region
        elif identity_client.audited_regions:
            first_region = identity_client.audited_regions[0]
            region = (
                first_region.key if hasattr(first_region, "key") else str(first_region)
            )

        # Create a report for the tenancy
        report = Check_Report_OCI(
            metadata=self.metadata(),
            resource={},
            region=region,
            resource_name="Instance Principal Configuration",
            resource_id=identity_client.audited_tenancy,
            compartment_id=identity_client.audited_tenancy,
        )

        # If there are valid dynamic groups for instance principals, PASS
        if valid_dynamic_groups:
            report.status = "PASS"
            report.status_extended = f"Dynamic Groups are configured for instance principal authentication. Found {len(valid_dynamic_groups)} dynamic group(s) with proper matching rules."
        else:
            report.status = "FAIL"
            report.status_extended = "No Dynamic Groups found with matching rules for instance principals (instances, functions, or databases)."

        findings.append(report)

        return findings
