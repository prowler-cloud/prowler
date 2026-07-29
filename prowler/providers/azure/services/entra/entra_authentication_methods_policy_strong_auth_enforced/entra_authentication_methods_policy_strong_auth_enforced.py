from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

# Methods considered strong (phishing-resistant or app-based MFA)
STRONG_METHODS = {"microsoftAuthenticator", "fido2", "x509Certificate"}


class entra_authentication_methods_policy_strong_auth_enforced(Check):
    """
    Ensure the Entra ID authentication methods policy enforces strong authentication.

    This check evaluates the tenant authentication methods policy and reports a single finding per tenant. Strong authentication is considered enforced only when BOTH conditions hold:
    1. The MFA registration campaign is enabled (users are prompted to register methods).
    2. At least one strong, phishing-resistant or app-based method (Microsoft Authenticator, FIDO2, or X.509 certificate) is enabled.

    - PASS: Both conditions hold.
    - FAIL: One or both conditions are missing; the status extended names exactly what is missing.
    """

    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, policy in entra_client.authentication_methods_policy.items():
            if policy is None:
                continue

            report = Check_Report_Azure(metadata=self.metadata(), resource=policy)
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = "Authentication Methods Policy"
            report.resource_id = policy.id

            registration_enabled = policy.registration_enforcement_state == "enabled"
            enabled_strong = [
                config.method_name
                for config in policy.method_configurations
                if config.state == "enabled" and config.method_name in STRONG_METHODS
            ]

            if registration_enabled and enabled_strong:
                report.status = "PASS"
                report.status_extended = (
                    f"Strong authentication is enforced for tenant {tenant_domain}: "
                    f"the MFA registration campaign is enabled and strong methods are "
                    f"enabled ({', '.join(enabled_strong)})."
                )
            else:
                issues = []
                if not registration_enabled:
                    issues.append("the MFA registration campaign is not enabled")
                if not enabled_strong:
                    issues.append(
                        "no strong authentication methods (Microsoft Authenticator, "
                        "FIDO2, or X.509 Certificate) are enabled"
                    )
                report.status = "FAIL"
                report.status_extended = (
                    f"Strong authentication is not enforced for tenant "
                    f"{tenant_domain}: {'; '.join(issues)}."
                )

            findings.append(report)

        return findings
