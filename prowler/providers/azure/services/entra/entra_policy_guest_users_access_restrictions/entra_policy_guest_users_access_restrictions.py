from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.config import GUEST_USER_ACCESS_RESTRICTICTED
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_guest_users_access_restrictions(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = getattr(auth_policy, "name", "Authorization Policy")
            report.resource_id = getattr(auth_policy, "id", "authorizationPolicy")
            report.status_extended = "Guest user access is not restricted to properties and memberships of their own directory objects"

            if (
                getattr(auth_policy, "guest_user_role_id", None)
                == GUEST_USER_ACCESS_RESTRICTICTED
            ):
                report.status = "PASS"
                report.status_extended = "Guest user access is restricted to properties and memberships of their own directory objects"

            findings.append(report)

        return findings
