from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_deletion_protection(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2:
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb.arn
            report.status = "FAIL"
            report.status_extended = f"ELBv2 {lb.name} has not deletion protection."
            if lb.deletion_protection == "true":
                report.status = "PASS"
                report.status_extended = (
                    f"ELBv2 {lb.name} has deletion protection enabled."
                )

            findings.append(report)

        return findings
