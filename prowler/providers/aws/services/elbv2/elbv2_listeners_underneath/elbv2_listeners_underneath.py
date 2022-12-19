from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_listeners_underneath(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2:
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.status = "PASS"
            report.status_extended = f"ELBv2 {lb.name} has listeners underneath."
            if len(lb.listeners) == 0:
                report.status = "FAIL"
                report.status_extended = f"ELBv2 {lb.name} has no listeners underneath."

            findings.append(report)

        return findings
