from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_logging_enabled(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
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
