from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.support.support_client import support_client


class support_plan_subscribed(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = "Premium support plan isn't subscribed."
        report.region = "global"
        for support_service in support_client.support_services:
            if support_service.premium_support:
                report.status = "PASS"
                report.status_extended = "Premium support plan is subscribed."
                break
        findings.append(report)
        return findings
