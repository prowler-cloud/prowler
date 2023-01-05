from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.trustedadvisor.trustedadvisor_client import (
    trustedadvisor_client,
)


class trustedadvisor_errors_and_warnings(Check):
    def execute(self):
        findings = []
        if trustedadvisor_client.enabled:
            if trustedadvisor_client.checks:
                for check in trustedadvisor_client.checks:
                    report = Check_Report_AWS(self.metadata())
                    report.region = check.region
                    report.resource_id = check.id
                    report.status = "FAIL"
                    report.status_extended = f"Trusted Advisor check {check.name} is in state {check.status}."
                    if check.status == "ok":
                        report.status = "PASS"
                    findings.append(report)
        else:
            report = Check_Report_AWS(self.metadata())
            report.status = "INFO"
            report.status_extended = "Amazon Web Services Premium Support Subscription is required to use this service."
            report.resource_id = trustedadvisor_client.account
            report.region = trustedadvisor_client.region
            findings.append(report)

        return findings
