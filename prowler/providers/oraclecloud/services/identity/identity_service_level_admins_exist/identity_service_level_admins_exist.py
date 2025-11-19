from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_service_level_admins_exist(Check):
    """Ensure service level admins are created to manage resources of particular service (CIS 1.1)"""

    def execute(self):
        """Ensure service level admins are created to manage resources of particular service.

        This check ensures that policies don't grant overly broad permissions like "manage all-resources"
        without being restricted to specific services or compartments.
        """
        findings = []

        # Check for policies that violate least privilege by granting manage all-resources
        for policy in identity_client.policies:
            # Skip non-active policies
            if policy.lifecycle_state != "ACTIVE":
                continue

            # Skip default tenant admin policy
            if policy.name.upper() == "TENANT ADMIN POLICY":
                continue

            region = policy.region if hasattr(policy, "region") else "global"

            has_violation = False
            for statement in policy.statements:
                statement_upper = statement.upper()

                # Check for "allow group ... to manage all-resources" (not specific to service/compartment)
                if (
                    "ALLOW GROUP" in statement_upper
                    and "TO MANAGE ALL-RESOURCES" in statement_upper
                ):
                    has_violation = True
                    break

            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=policy,
                region=region,
                resource_id=policy.id,
                resource_name=policy.name,
                compartment_id=policy.compartment_id,
            )

            if has_violation:
                report.status = "FAIL"
                report.status_extended = f"Policy '{policy.name}' grants 'manage all-resources' permissions. Service-level administrators should be created with permissions limited to specific services (e.g., manage instance-family, manage volume-family) in specific compartments."
            else:
                report.status = "PASS"
                report.status_extended = f"Policy '{policy.name}' follows least privilege principle by not granting broad 'manage all-resources' permissions."

            findings.append(report)

        # If no policies found, that's also a finding
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
                resource_id=identity_client.audited_tenancy,
                resource_name="Tenancy",
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "PASS"
            report.status_extended = (
                "No active policies found with overly broad permissions."
            )
            findings.append(report)

        return findings
