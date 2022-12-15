from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.macie.macie_client import macie_client


class macie_is_enabled(Check):
    def execute(self):
        findings = []
        for session in macie_client.sessions:
            report = Check_Report_AWS(self.metadata())
            report.region = session.region
            report.resource_id = "Macie"
            if session.status == "ENABLED":
                report.status = "PASS"
                report.status_extended = "Macie is enabled."
            elif session.status == "PAUSED":
                report.status = "FAIL"
                report.status_extended = "Macie is currently in a SUSPENDED state."
            else:
                report.status = "FAIL"
                report.status_extended = "Macie is not enabled."
            findings.append(report)

        return findings
