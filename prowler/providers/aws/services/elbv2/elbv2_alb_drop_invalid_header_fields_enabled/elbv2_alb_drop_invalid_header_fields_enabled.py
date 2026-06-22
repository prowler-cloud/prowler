from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_alb_drop_invalid_header_fields_enabled(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            if lb.type == "application":
                report = Check_Report_AWS(
                    metadata=self.metadata(),
                    resource=lb,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"ELBv2 ALB {lb.name} is configured to drop invalid "
                    "header fields."
                )
                if lb.drop_invalid_header_fields != "true":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ELBv2 ALB {lb.name} is not configured to drop "
                        "invalid header fields."
                    )
                findings.append(report)

        return findings
