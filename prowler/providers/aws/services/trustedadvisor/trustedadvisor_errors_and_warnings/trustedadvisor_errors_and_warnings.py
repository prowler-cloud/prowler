from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_client import (
    trustedadvisor_client,
)


class trustedadvisor_errors_and_warnings(Check):
    def execute(self):
        findings = []
        if trustedadvisor_client.checks:
            for check in trustedadvisor_client.checks:
                report = Check_Report(self.metadata())
                report.region = check.region
                report.resource_id = check.id
                report.status = "FAIL"
                report.status_extended = (
                    f"Trusted Advisor check {check.name} is in state {check.status}."
                )
                if check.status == "ok":
                    report.status = "PASS"
                findings.append(report)

        return findings
