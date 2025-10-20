"""Check Ensure permissions on all resources are given only to the tenancy administrator group."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_tenancy_admin_permissions_limited(Check):
    """Check Ensure permissions on all resources are given only to the tenancy administrator group."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_tenancy_admin_permissions_limited check.

        Ensure permissions on all resources are given only to the tenancy administrator group.
        This check verifies that only the 'Tenant Admin Policy' grants 'manage all-resources in tenancy' permissions.
        Other policies should not have such broad permissions.
        """
        findings = []

        # Check for policies that grant "manage all-resources in tenancy"
        for policy in identity_client.policies:
            # Skip non-active policies
            if policy.lifecycle_state != "ACTIVE":
                continue

            region = policy.region if hasattr(policy, "region") else "global"

            has_violation = False
            for statement in policy.statements:
                statement_upper = statement.upper()

                # Check for "allow group ... to manage all-resources in tenancy"
                # This should only be in "Tenant Admin Policy"
                if (
                    "ALLOW GROUP" in statement_upper
                    and "TO MANAGE ALL-RESOURCES IN TENANCY" in statement_upper
                ):
                    # If this is not the Tenant Admin Policy, it's a violation
                    if policy.name.upper() != "TENANT ADMIN POLICY":
                        has_violation = True
                    break

            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=policy,
                region=region,
                resource_name=policy.name,
                resource_id=policy.id,
                compartment_id=policy.compartment_id,
            )

            if has_violation:
                report.status = "FAIL"
                report.status_extended = f"Policy '{policy.name}' grants 'manage all-resources in tenancy' permissions to groups other than the Administrators group. Only the tenancy administrator group should have such broad permissions."
            else:
                report.status = "PASS"
                report.status_extended = f"Policy '{policy.name}' does not grant overly broad tenancy-wide permissions to non-administrator groups."

            findings.append(report)

        # If no policies found, that's a PASS (no violations)
        if not findings:
            region = (
                identity_client.audited_regions[0].key
                if identity_client.audited_regions
                else "global"
            )
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region=region,
                resource_name="Tenancy",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "PASS"
            report.status_extended = "No active policies found granting overly broad tenancy-wide permissions to non-administrator groups."
            findings.append(report)

        return findings
