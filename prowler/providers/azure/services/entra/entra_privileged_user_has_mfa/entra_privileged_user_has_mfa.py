from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_privileged_user_has_mfa(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, users in entra_client.users.items():
            for user_domain_name, user in users.items():
                is_privileged = False

                for directory_role in entra_client.directory_roles[
                    tenant_domain
                ].values():
                    if user in directory_role.members:
                        is_privileged = True
                        break

                if is_privileged:
                    report = Check_Report_Azure(self.metadata())
                    report.status = "FAIL"
                    report.subscription = f"Tenant: {tenant_domain}"
                    report.resource_name = user_domain_name
                    report.resource_id = user.id
                    report.status_extended = (
                        f"User '{user.name}' does not have MFA enabled."
                    )

                    if len(user.authentication_methods) > 1:
                        report.status = "PASS"
                        report.status_extended = f"User '{user.name}' has MFA enabled."

                    findings.append(report)

        return findings
