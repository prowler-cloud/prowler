from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_cross_zone_load_balancing_enabled(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for lb_arn, lb in elbv2_client.loadbalancersv2.items():
            if lb.type != "application":
                report = Check_Report_AWS(self.metadata())
                report.region = lb.region
                report.resource_id = lb.name
                report.resource_arn = lb_arn
                report.resource_tags = lb.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"ELBv2 {lb.name} does not have cross-zone load balancing enabled."
                )
                if lb.cross_zone_load_balancing == "true":
                    report.status = "PASS"
                    report.status_extended = (
                        f"ELBv2 {lb.name} has cross-zone load balancing enabled."
                    )

                findings.append(report)

        return findings
