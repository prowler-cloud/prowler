from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instances_in_vpc(Check):
    def execute(self):
        findings = []

        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags

            # Check if instance has a VPC ID
            if instance.vpc_id:
                report.status = "PASS"
                report.status_extended = f"EC2 instance {instance.id} is running inside VPC {instance.vpc_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"EC2 instance {instance.id} is not running inside a VPC."

            findings.append(report)

        return findings
