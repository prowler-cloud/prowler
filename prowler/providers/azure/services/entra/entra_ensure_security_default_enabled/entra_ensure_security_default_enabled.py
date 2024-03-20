from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_ensure_security_default_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            tenant,
            security_default,
        ) in entra_client.security_default.items():
            report = Check_Report_Azure(self.metadata())
            report.status = "PASS"
            report.subscription = f"Tenant: '{tenant}'"
            report.resource_name = security_default.name
            report.resource_id = security_default.id
            report.status_extended = "Entra security defaults is enabled."

            if not security_default.is_enabled:
                report.status = "FAIL"
                report.status_extended = "Entra security defaults is not enabled."

            findings.append(report)

        return findings
