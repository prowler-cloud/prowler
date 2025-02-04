from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_is_in_multiple_az(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        elbv2_min_azs = elbv2_client.audit_config.get("elbv2_min_azs", 2)
        for lb in elbv2_client.loadbalancersv2.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
            report.status = "FAIL"
            report.status_extended = f"ELBv2 {lb.name} is not in at least {elbv2_min_azs} AZs. Is only in {', '.join(lb.availability_zones.keys())}."

            if len(lb.availability_zones) >= elbv2_min_azs:
                report.status = "PASS"
                report.status_extended = f"ELBv2 {lb.name} is at least in {elbv2_min_azs} AZs: {', '.join(lb.availability_zones.keys())}."

            findings.append(report)

        return findings
