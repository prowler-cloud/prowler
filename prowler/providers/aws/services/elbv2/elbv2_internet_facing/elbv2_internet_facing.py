from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_internet_facing(Check):
    def execute(self):
        findings = []
        for lb_arn, lb in elbv2_client.loadbalancersv2.items():
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.resource_arn = lb_arn
            report.resource_tags = lb.tags
            report.status = "PASS"
            report.status_extended = f"ELBv2 ALB {lb.name} is not internet facing."
            if lb.scheme == "internet-facing":
                report.status_extended = f"ELBv2 ALB {lb.name} has an internet facing scheme with domain {lb.dns} but is not public."
                for sg_id in getattr(lb, "security_groups", []):
                    sg_arn = f"arn:{elbv2_client.audited_partition}:ec2:{lb.region}:{elbv2_client.audited_account}:security-group/{sg_id}"
                    if sg_arn in ec2_client.security_groups:
                        for ingress_rule in ec2_client.security_groups[
                            sg_arn
                        ].ingress_rules:
                            if check_security_group(
                                ingress_rule, "tcp", any_address=True
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"ELBv2 ALB {lb.name} is internet facing with domain {lb.dns} due to their security group {sg_id} is public."

            findings.append(report)

        return findings
