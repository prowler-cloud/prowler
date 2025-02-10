from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.entra.entra_client import entra_client


class entra_security_defaults_enabled(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []
        report = Check_Report_Microsoft365(
            metadata=self.metadata(), resource=entra_client.security_defaults
        )
        report.status = "FAIL"
        report.status_extended = "Entra Security Defaults is disabled."

        if (
            entra_client.security_defaults is not None
            and entra_client.security_defaults.is_enabled
        ):
            report.status = "PASS"
            report.status_extended = "Entra Security Defaults is enabled."

        findings.append(report)
        return findings
