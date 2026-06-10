from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_user_consent_for_verified_apps(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(metadata=self.metadata(), resource=auth_policy)
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = getattr(auth_policy, "name", "Authorization Policy")
            report.resource_id = auth_policy.id
            report.status = "PASS"
            report.status_extended = "Entra does not allow users to consent non-verified apps accessing company data on their behalf."

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
                report.status_extended = "Entra allows users to consent apps accessing company data on their behalf."

            findings.append(report)

        return findings
