from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_cross_zone_load_balancing_enabled(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for load_balancer_arn, load_balancer in elb_client.loadbalancers.items():
            report = Check_Report_AWS(self.metadata())
            report.region = load_balancer.region
            report.resource_id = load_balancer.name
            report.resource_arn = load_balancer_arn
            report.resource_tags = load_balancer.tags
            report.status = "FAIL"
            report.status_extended = f"ELB {load_balancer.name} does not have cross-zone load balancing enabled."

            if load_balancer.cross_zone_load_balancing:
                report.status = "PASS"
                report.status_extended = (
                    f"ELB {load_balancer.name} has cross-zone load balancing enabled."
                )

            findings.append(report)

        return findings
