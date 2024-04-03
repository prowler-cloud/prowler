from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_security_defaults_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            tenant,
            security_default,
        ) in entra_client.security_default.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant}"
            report.resource_name = getattr(security_default, "name", "Security Default")
            report.resource_id = getattr(security_default, "id", "Security Default")
            report.status_extended = "Entra security defaults is diabled."

            if getattr(security_default, "is_enabled", False):
                report.status = "PASS"
                report.status_extended = "Entra security defaults is enabled."

            findings.append(report)

        return findings
