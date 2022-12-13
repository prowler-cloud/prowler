from prowler.lib.check.models import Check, Check_Report
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_logging_enabled(Check):
    def execute(self):
        findings = []
        for lb in elb_client.loadbalancers:
            report = Check_Report(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.status = "FAIL"
            report.status_extended = f"ELB {lb.name} has not configured access logs."
            if lb.access_logs:
                report.status = "PASS"
                report.status_extended = (
                    f"ELB {lb.name} has access logs to S3 configured."
                )

            findings.append(report)

        return findings
