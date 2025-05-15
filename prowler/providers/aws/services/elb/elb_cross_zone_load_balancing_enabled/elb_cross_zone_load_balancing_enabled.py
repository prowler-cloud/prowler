from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_cross_zone_load_balancing_enabled(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "FAIL"
            report.status_extended = (
                f"ELB {lb.name} does not have cross-zone load balancing enabled."
            )

            if lb.cross_zone_load_balancing:
                report.status = "PASS"
                report.status_extended = (
                    f"ELB {lb.name} has cross-zone load balancing enabled."
                )

            findings.append(report)

        return findings
