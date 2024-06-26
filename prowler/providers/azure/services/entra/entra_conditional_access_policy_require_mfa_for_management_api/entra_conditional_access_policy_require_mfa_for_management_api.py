from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.config import WINDOWS_AZURE_SERVICE_MANAGEMENT_API
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_conditional_access_policy_require_mfa_for_management_api(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            tenant_name,
            conditional_access_policies,
        ) in entra_client.conditional_access_policy.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant_name}"
            report.resource_name = "Conditional Access Policy"
            report.resource_id = "Conditional Access Policy"
            report.status_extended = (
                "Conditional Access Policy does not require MFA for management API."
            )

            for policy_id, policy in conditional_access_policies.items():
                if (
                    policy.state == "enabled"
                    and "All" in policy.users["include"]
                    and WINDOWS_AZURE_SERVICE_MANAGEMENT_API
                    in policy.target_resources["include"]
                    and any(
                        "mfa" in access_control.lower()
                        for access_control in policy.access_controls["grant"]
                    )
                ):
                    report.status = "PASS"
                    report.status_extended = (
                        "Conditional Access Policy requires MFA for management API."
                    )
                    report.resource_id = policy_id
                    report.resource_name = policy.name
                    break

            findings.append(report)

        return findings
