from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_global_admin_in_less_than_five_users(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, directory_roles in entra_client.directory_roles.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant_domain}"
            report.resource_name = "Global Administrator"

            if "Global Administrator" in directory_roles:
                report.resource_id = getattr(
                    directory_roles["Global Administrator"],
                    "id",
                    "Global Administrator",
                )

                num_global_admins = len(
                    getattr(directory_roles["Global Administrator"], "members", [])
                )

                if num_global_admins < 5:
                    report.status = "PASS"
                    report.status_extended = (
                        f"There are {num_global_admins} global administrators."
                    )
                else:
                    report.status_extended = f"There are {num_global_admins} global administrators. It should be less than five."

                findings.append(report)

        return findings
