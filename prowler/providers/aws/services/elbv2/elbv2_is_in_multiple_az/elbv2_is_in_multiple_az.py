from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_is_in_multiple_az(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        elbv2_min_azs = elbv2_client.audit_config.get("elbv2_min_azs", 2)
        for load_balancer_arn, load_balancer in elbv2_client.loadbalancersv2.items():
            report = Check_Report_AWS(self.metadata())
            report.region = load_balancer.region
            report.resource_id = load_balancer.name
            report.resource_arn = load_balancer_arn
            report.resource_tags = load_balancer.tags
            report.status = "FAIL"
            report.status_extended = f"ELBv2 {load_balancer.name} is not in at least {elbv2_min_azs} AZs. Is only in {', '.join(load_balancer.availability_zones.keys())}."

            if len(load_balancer.availability_zones) >= elbv2_min_azs:
                report.status = "PASS"
                report.status_extended = f"ELBv2 {load_balancer.name} is at least in {elbv2_min_azs} AZs: {', '.join(load_balancer.availability_zones.keys())}."

            findings.append(report)

        return findings
