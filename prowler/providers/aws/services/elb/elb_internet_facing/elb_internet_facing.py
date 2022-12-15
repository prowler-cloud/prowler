from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_internet_facing(Check):
    def execute(self):
        findings = []
        for lb in elb_client.loadbalancers:
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.status = "PASS"
            report.status_extended = f"ELB {lb.name} is not internet facing."
            if lb.scheme == "internet-facing":
                report.status = "FAIL"
                report.status_extended = (
                    f"ELB {lb.name} is internet facing in {lb.dns}."
                )

            findings.append(report)

        return findings
