from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_desync_mitigation_mode(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2:
            if lb.type == "application":
                report = Check_Report_AWS(self.metadata())
                report.region = lb.region
                report.resource_id = lb.name
                report.resource_arn = lb.arn
                report.status = "PASS"
                report.status_extended = f"ELBv2 ALB {lb.name} is configured with correct desync mitigation mode."
                if lb.desync_mitigation_mode == "monitor":
                    report.status = "FAIL"
                    report.status_extended = f"ELBv2 ALB {lb.name} does not have desync mitigation mode set as defensive or strictest."

                findings.append(report)

        return findings
