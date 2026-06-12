from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client

# Methods considered strong (phishing-resistant or app-based MFA)
STRONG_METHODS = {"microsoftAuthenticator", "fido2", "x509Certificate"}


class entra_authentication_methods_policy_strong_auth_enforced(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, policy in (
            entra_client.authentication_methods_policy.items()
        ):
            if policy is None:
                continue

            # Check 1: Is MFA registration enforcement enabled?
            report_registration = Check_Report_Azure(
                metadata=self.metadata(), resource=policy
            )
            report_registration.subscription = f"Tenant: {tenant_domain}"
            report_registration.resource_name = "MFA Registration Campaign"
            report_registration.resource_id = policy.id

            if policy.registration_enforcement_state == "enabled":
                report_registration.status = "PASS"
                report_registration.status_extended = (
                    "MFA registration campaign is enabled — users are prompted "
                    "to register authentication methods."
                )
            else:
                report_registration.status = "FAIL"
                report_registration.status_extended = (
                    "MFA registration campaign is not enabled — users are not "
                    "prompted to register authentication methods."
                )

            findings.append(report_registration)

            # Check 2: Is at least one strong auth method enabled?
            enabled_strong = [
                config.method_name
                for config in policy.method_configurations
                if config.state == "enabled"
                and config.method_name in STRONG_METHODS
            ]

            report_strong = Check_Report_Azure(
                metadata=self.metadata(), resource=policy
            )
            report_strong.subscription = f"Tenant: {tenant_domain}"
            report_strong.resource_name = "Strong Authentication Methods"
            report_strong.resource_id = policy.id

            if enabled_strong:
                report_strong.status = "PASS"
                report_strong.status_extended = (
                    f"Strong authentication methods enabled: "
                    f"{', '.join(enabled_strong)}."
                )
            else:
                report_strong.status = "FAIL"
                report_strong.status_extended = (
                    "No strong authentication methods (Microsoft Authenticator, "
                    "FIDO2, or X.509 Certificate) are enabled."
                )

            findings.append(report_strong)

        return findings
