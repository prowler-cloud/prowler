from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_ensure_default_user_cannot_create_tenants(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():

            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"All from tenant '{tenant_domain}'"
            report.resource_name = auth_policy.name
            report.resource_id = auth_policy.id
            report.status_extended = (
                "Tenants creation is not disabled for non-admin users."
            )

            if auth_policy.default_user_role_permissions and not getattr(
                auth_policy.default_user_role_permissions,
                "allowed_to_create_tenants",
                True,
            ):
                report.status = "PASS"
                report.status_extended = (
                    "Tenants creation is disabled for non-admin users."
                )

            findings.append(report)

        return findings
