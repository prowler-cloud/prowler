from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_thirdparty_integrated_apps_not_allowed(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []

        auth_policy = entra_client.authorization_policy
        report = Check_Report_Microsoft365(self.metadata(), auth_policy)
        report.status = "FAIL"
        report.status_extended = "App creation is not disabled for non-admin users."

        if getattr(auth_policy, "default_user_role_permissions", None) and not getattr(
            auth_policy.default_user_role_permissions,
            "allowed_to_create_apps",
            True,
        ):
            report.status = "PASS"
            report.status_extended = "App creation is disabled for non-admin users."

        findings.append(report)

        return findings
