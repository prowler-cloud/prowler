from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_guest_invite_only_for_admin_roles(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(metadata=self.metadata(), resource=auth_policy)
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = getattr(auth_policy, "name", "Authorization Policy")
            report.resource_id = auth_policy.id
            report.status = "FAIL"
            report.status_extended = "Guest invitations are not restricted to users with specific administrative roles only."

            if (
                getattr(auth_policy, "guest_invite_settings", "everyone")
                == "adminsAndGuestInviters"
                or getattr(auth_policy, "guest_invite_settings", "everyone") == "none"
            ):
                report.status = "PASS"
                report.status_extended = "Guest invitations are restricted to users with specific administrative roles only."

            findings.append(report)

        return findings
