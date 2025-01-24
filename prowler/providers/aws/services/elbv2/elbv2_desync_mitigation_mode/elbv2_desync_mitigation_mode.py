from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_desync_mitigation_mode(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            if lb.type == "application":
                report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
                report.status = "PASS"
                report.status_extended = f"ELBv2 ALB {lb.name} is configured with correct desync mitigation mode."
                if (
                    lb.desync_mitigation_mode != "strictest"
                    or lb.desync_mitigation_mode != "defensive"
                ):
                    if lb.drop_invalid_header_fields == "false":
                        report.status = "FAIL"
                        report.status_extended = f"ELBv2 ALB {lb.name} does not have desync mitigation mode set as strictest/defensive and is not dropping invalid header fields."
                    elif lb.drop_invalid_header_fields == "true":
                        report.status_extended = f"ELBv2 ALB {lb.name} does not have desync mitigation mode set as strictest/defensive but is dropping invalid header fields."
                findings.append(report)

        return findings
