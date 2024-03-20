from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_esure_there_are_less_than_five_global_admins(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant_domain, directory_roles in entra_client.directory_roles.items():
            if "Global Administrator" in directory_roles:
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = f"Tenant: '{tenant_domain}'"
                report.resource = "Global Administrators"
                report.id = getattr(
                    directory_roles["Global Administrator"], "id", "N/A"
                )
                report.status_extended = (
                    "There are less than five global administrators."
                )

                if (
                    len(getattr(directory_roles["Global Administrator"], "members", []))
                    >= 5
                ):
                    report.status = "FAIL"
                    report.status_extended = (
                        "There are more than five global administrators."
                    )

                findings.append(report)

        return findings
