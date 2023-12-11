from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_instance_type_optimized(Check):
    def execute(self):
        findings = []

        # List of optimized instance types (modify as needed)
        optimized_instance_types = ["t3.micro", "t3.small", "t3.medium"]

        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags

            report.status = "PASS"
            report.status_extended = f"EC2 instance {instance.id} is using an optimized instance type."

            # Get the instance type
            instance_type = instance.instance_type

            # Check if the instance type is in the list of optimized instance types
            if instance_type not in optimized_instance_types:
                report.status = "FAIL"
                report.status_extended = f"EC2 instance {instance.id} is not using an optimized instance type. Current type: {instance_type}"

            findings.append(report)

        return findings