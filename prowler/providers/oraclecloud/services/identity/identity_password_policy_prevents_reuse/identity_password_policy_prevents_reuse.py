"""Check Ensure IAM password policy prevents password reuse."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_password_policy_prevents_reuse(Check):
    """Check Ensure IAM password policy prevents password reuse."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_password_policy_prevents_reuse check.

        Note: Password reuse prevention is only available in OCI Identity Domains.
        The legacy IAM password policy does not support password history.
        """
        findings = []

        # This check only applies to Identity Domains, not the legacy password policy

        # If no Identity Domains are found, the legacy password policy is in use
        if not identity_client.domains:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region="global",
                resource_name="Password Reuse Policy",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "MANUAL"
            report.status_extended = "Identity Domains not enabled. Password reuse prevention is only available in OCI Identity Domains. Legacy password policy does not support password history."
            findings.append(report)
            return findings

        # Check each Identity Domain's password policies
        for domain in identity_client.domains:
            region = domain.region if hasattr(domain, "region") else "global"

            if not domain.password_policies:
                report = Check_Report_OCI(
                    metadata=self.metadata(),
                    resource={},
                    region=region,
                    resource_name=f"Domain: {domain.display_name}",
                    resource_id=domain.id,
                    compartment_id=domain.compartment_id,
                )
                report.status = "FAIL"
                report.status_extended = f"Identity Domain '{domain.display_name}' has no password policy configured."
                findings.append(report)
            else:
                for policy in domain.password_policies:
                    report = Check_Report_OCI(
                        metadata=self.metadata(),
                        resource=policy,
                        region=region,
                        resource_name=f"Domain: {domain.display_name} - Policy: {policy.name}",
                        resource_id=policy.id,
                        compartment_id=domain.compartment_id,
                    )

                    # Check if password history is configured (CIS recommends 24 passwords)
                    if policy.num_passwords_in_history is None:
                        report.status = "FAIL"
                        report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' does not have password history configured."
                    elif policy.num_passwords_in_history < 24:
                        report.status = "FAIL"
                        report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' remembers {policy.num_passwords_in_history} passwords, which is less than the recommended 24."
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' prevents password reuse by remembering {policy.num_passwords_in_history} passwords."

                    findings.append(report)

        return findings
