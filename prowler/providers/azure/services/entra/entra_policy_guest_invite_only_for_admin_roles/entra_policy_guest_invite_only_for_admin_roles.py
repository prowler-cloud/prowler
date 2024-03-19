from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_guest_invite_only_for_admin_roles(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: '{tenant_domain}'"
            report.resource_name = auth_policy.name
            report.resource_id = auth_policy.id
            report.status_extended = (
                "Guest invite settings are not restricted for admins roles only"
            )

            if (
                auth_policy.guest_invite_settings == "adminsAndGuestInviters"
                or auth_policy.guest_invite_settings == "none"
            ):
                report.status = "PASS"
                report.status_extended = (
                    "Guest invite settings are restricted for admins roles only"
                )

            findings.append(report)

        return findings
