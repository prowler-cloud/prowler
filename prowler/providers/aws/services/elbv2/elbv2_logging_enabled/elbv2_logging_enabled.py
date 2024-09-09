from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_logging_enabled(Check):
    def execute(self):
        findings = []
        for lb_arn, lb in elbv2_client.loadbalancersv2.items():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb_arn
            report.resource_tags = lb.tags
            report.status = "FAIL"
            report.status_extended = (
                f"ELBv2 ALB {lb.name} does not have access logs configured."
            )
            if lb.access_logs == "true":
                report.status = "PASS"
                report.status_extended = (
                    f"ELBv2 ALB {lb.name} has access logs to S3 configured."
                )

            findings.append(report)

        return findings
