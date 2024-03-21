from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_user_consent_for_verified_apps(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "PASS"
            report.subscription = f"Tenant: '{tenant_domain}'"
            report.resource_name = getattr(auth_policy, "name", "Authorization Policy")
            report.resource_id = getattr(auth_policy, "id", "authorizationPolicy")
            report.status_extended = "All users can consent for permissions classified as 'low impact', for apps from verified publishers or apps registered in this organization or require administrator to consent."

            if getattr(auth_policy, "default_user_role_permissions", None) and any(
                "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
                in policy_assigned
                for policy_assigned in getattr(
                    auth_policy.default_user_role_permissions,
                    "permission_grant_policies_assigned",
                    ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
                )
            ):
                report.status = "FAIL"
                report.status_extended = "All users can consent for any app to access the organization's data."

            findings.append(report)

        return findings
