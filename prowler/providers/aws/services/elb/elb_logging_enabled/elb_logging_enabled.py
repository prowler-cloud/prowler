from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_logging_enabled(Check):
    def execute(self):
        findings = []
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=lb)
            report.status = "FAIL"
            report.status_extended = (
                f"ELB {lb.name} does not have access logs configured."
            )
            if lb.access_logs:
                report.status = "PASS"
                report.status_extended = (
                    f"ELB {lb.name} has access logs to S3 configured."
                )

            findings.append(report)

        return findings
