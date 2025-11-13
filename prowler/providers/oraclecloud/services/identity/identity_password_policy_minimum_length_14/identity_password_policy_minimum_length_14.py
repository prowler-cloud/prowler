"""Check if IAM password policy requires minimum length of 14 or greater."""

from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.identity.identity_client import (
    identity_client,
)


class identity_password_policy_minimum_length_14(Check):
    """Check if IAM password policy requires minimum length of 14 or greater."""

    def execute(self) -> Check_Report_OCI:
        """Execute the identity_password_policy_minimum_length_14 check.

        Returns:
            List of Check_Report_OCI objects with findings
        """
        findings = []

        # Prioritize Identity Domains password policies if available

        # Check Identity Domains first
        if identity_client.domains:
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

                        # Check if minimum password length is 14 or greater
                        if policy.min_length and policy.min_length >= 14:
                            report.status = "PASS"
                            report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' requires minimum length of {policy.min_length} characters."
                        else:
                            report.status = "FAIL"
                            min_len = (
                                policy.min_length if policy.min_length else "not set"
                            )
                            report.status_extended = f"Password policy '{policy.name}' in domain '{domain.display_name}' requires minimum length of {min_len} characters, which is less than 14."

                        findings.append(report)

        # Fallback to legacy password policy if no Identity Domains
        elif identity_client.password_policy:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=identity_client.password_policy,
                region=identity_client.provider.identity.region,
                resource_name="Password Policy (Legacy)",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )

            # Check if minimum password length is 14 or greater
            if identity_client.password_policy.minimum_password_length >= 14:
                report.status = "PASS"
                report.status_extended = f"Legacy IAM password policy requires minimum length of {identity_client.password_policy.minimum_password_length} characters."
            else:
                report.status = "FAIL"
                report.status_extended = f"Legacy IAM password policy requires minimum length of {identity_client.password_policy.minimum_password_length} characters, which is less than 14."

            findings.append(report)
        else:
            # No password policy found at all
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource={},
                region=identity_client.provider.identity.region,
                resource_name="Password Policy",
                resource_id=identity_client.audited_tenancy,
                compartment_id=identity_client.audited_tenancy,
            )
            report.status = "FAIL"
            report.status_extended = "No password policy configured for the tenancy."
            findings.append(report)

        return findings
