"""Check Ensure IAM password policy expires passwords within 365 days."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_password_policy_expires_within_365_days(Check):
    """Check Ensure IAM password policy expires passwords within 365 days."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_password_policy_expires_within_365_days check.

        Note: Password expiration policies are only available in OCI Identity Domains.
        The legacy IAM password policy does not support password expiration settings.
        This check requires Identity Domains to be enabled in the tenancy.
        """
        findings = []

        # This check only applies to Identity Domains, not the legacy password policy

        # If no Identity Domains are found, the legacy password policy is in use
        if not identity_client.domains:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region="global",
                resource_name="Password Expiration Policy",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "MANUAL"
            report.status_extended = "Identity Domains not enabled. Password expiration policies are only available in OCI Identity Domains. Legacy password policy does not support password expiration."
            findings.append(report)
            return findings

        # Check each Identity Domain's password policies
        for domain in identity_client.domains:
            # Determine the region
            region = domain.region if hasattr(domain, "region") else "global"

            # Check each password policy in the domain
            for policy in domain.password_policies:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource=policy,
                    region=region,
                    resource_name=f"Domain: {domain.display_name} - Policy: {policy.name}",
                    resource_id=policy.id,
                    compartment_id=domain.compartment_id,
                )

                # Check if password expiration is configured
                if policy.password_expires_after is None:
                    report.status = "FAIL"
                    report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' does not have password expiration configured."
                elif policy.password_expires_after > 365:
                    report.status = "FAIL"
                    report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' allows passwords to expire after {policy.password_expires_after} days, which exceeds the recommended 365 days."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' expires passwords within {policy.password_expires_after} days."

                findings.append(report)

        return findings
