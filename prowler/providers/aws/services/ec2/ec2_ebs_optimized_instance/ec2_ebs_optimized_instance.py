from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_ebs_optimized_instance(Check):
    def execute(self):
        findings = []

        # Iterate through EC2 instances
        for instance in ec2_client.instances:
            if instance.state != "running":
                continue

            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags

            # Check if the instance is EBS-optimized
            if hasattr(instance, "ebs_optimized") and instance.ebs_optimized:
                report.status = "PASS"
                report.status_extended = f"EC2 instance {instance.id} is EBS-optimized."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 instance {instance.id} is not EBS-optimized."
                )

            findings.append(report)

        return findings
