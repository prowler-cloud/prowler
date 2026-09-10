from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client
from prowler.providers.azure.services.entra.lib.user_privileges import (
    is_privileged_user,
)


class entra_non_privileged_user_has_mfa(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, users in entra_client.users.items():
            if tenant_domain in entra_client.users_retrieval_errors:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = tenant_domain
                report.resource_id = entra_client.tenant_ids[0]
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot evaluate MFA for the tenant's non-privileged users for tenant {tenant_domain}: "
                    f"Microsoft Graph did not return the tenant's users "
                    f"({entra_client.users_retrieval_errors[tenant_domain]}). "
                    f"Retry the scan or review the tenant's users manually."
                )
                findings.append(report)
                continue

            for user in users.values():
                if user.account_enabled and not is_privileged_user(
                    user, entra_client.directory_roles[tenant_domain]
                ):
                    report = Check_Report_Azure(metadata=self.metadata(), resource=user)
                    report.subscription = f"Tenant: {tenant_domain}"
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Non-privileged user {user.name} does not have MFA."
                    )

                    if user.is_mfa_capable:
                        report.status = "PASS"
                        report.status_extended = (
                            f"Non-privileged user {user.name} has MFA."
                        )

                    findings.append(report)

        return findings
