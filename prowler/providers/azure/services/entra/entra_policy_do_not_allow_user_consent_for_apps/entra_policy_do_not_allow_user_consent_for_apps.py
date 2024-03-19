from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_policy_do_not_allow_user_consent_for_apps(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, auth_policy in entra_client.authorization_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: '{tenant_domain}'"
            report.resource_name = auth_policy.name
            report.resource_id = auth_policy.id
            report.status_extended = "Allow user consent for apps is not disabled"

            if auth_policy.default_user_role_permissions and not any(
                "ManagePermissionGrantsForSelf" in policy_assigned
                for policy_assigned in getattr(
                    auth_policy.default_user_role_permissions,
                    "permission_grant_policies_assigned",
                    ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
                )
            ):
                report.status = "PASS"
                report.status_extended = "Allow user consent for apps is disabled"

            findings.append(report)

        return findings
