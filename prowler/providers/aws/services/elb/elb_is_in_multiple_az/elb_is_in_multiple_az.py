from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client

# https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/ELB/ec2-instances-distribution-across-availability-zones.html
# https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html#elb-10


class elb_is_in_multiple_az(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        ELB_MIN_AZS = elb_client.audit_config.get("elb_min_azs", 2)
        for loadbalancer_arn, load_balancer in elb_client.loadbalancers.items():
            report = Check_Report_AWS(self.metadata())
            report.region = load_balancer.region
            report.resource_id = load_balancer.name
            report.resource_arn = loadbalancer_arn
            report.resource_tags = load_balancer.tags
            report.status = "FAIL"
            report.status_extended = f"Classic Load Balancer {load_balancer.name} is not in at least {ELB_MIN_AZS} availability zones. Is only in {', '.join(load_balancer.availability_zones)}."

            if len(load_balancer.availability_zones) >= ELB_MIN_AZS:
                report.status = "PASS"
                report.status_extended = f"Classic Load Balancer {load_balancer.name} is in {len(load_balancer.availability_zones)} availability zones. Currently in {', '.join(load_balancer.availability_zones)}."

            findings.append(report)

        return findings
