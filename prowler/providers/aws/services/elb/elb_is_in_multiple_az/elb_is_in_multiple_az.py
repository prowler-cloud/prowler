from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_is_in_multiple_az(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        ELB_MIN_AZS = elb_client.audit_config.get("elb_min_azs", 2)
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "FAIL"
            report.status_extended = f"Classic Load Balancer {lb.name} is not in at least {ELB_MIN_AZS} availability zones, it is only in {', '.join(lb.availability_zones)}."

            if len(lb.availability_zones) >= ELB_MIN_AZS:
                report.status = "PASS"
                report.status_extended = f"Classic Load Balancer {lb.name} is in {len(lb.availability_zones)} availability zones: {', '.join(lb.availability_zones)}."

            findings.append(report)

        return findings
