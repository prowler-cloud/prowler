from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_desync_mitigation_mode(Check):
    def execute(self):
        findings = []
        for lb_arn, lb in elb_client.loadbalancers.items():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb_arn
            report.resource_tags = lb.tags
            if (
                lb.desync_mitigation_mode == "defensive"
                or lb.desync_mitigation_mode == "strictest"
            ):
                report.status = "PASS"
                report.status_extended = f"ELB {lb.name} has desync mitigation mode set to {lb.desync_mitigation_mode}."
            else:
                report.status = "FAIL"
                report.status_extended = f"ELB {lb.name} has desync mitigation mode set to {lb.desync_mitigation_mode}, not to strictest or defensive."

            findings.append(report)

        return findings
