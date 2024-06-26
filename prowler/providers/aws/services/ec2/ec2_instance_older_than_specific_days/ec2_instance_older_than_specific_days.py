from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_older_than_specific_days(Check):
    def execute(self):
        findings = []

        # max_ec2_instance_age_in_days, default: 180 days
        max_ec2_instance_age_in_days = ec2_client.audit_config.get(
            "max_ec2_instance_age_in_days", 180
        )
        for instance in ec2_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = f"EC2 Instance {instance.id} is not running."
            if instance.state == "running":
                time_since_launch = (
                    datetime.now().replace(tzinfo=timezone.utc) - instance.launch_time
                )
                report.status_extended = f"EC2 Instance {instance.id} is not older than {max_ec2_instance_age_in_days} days ({time_since_launch.days} days)."
                if time_since_launch.days > max_ec2_instance_age_in_days:
                    report.status = "FAIL"
                    report.status_extended = f"EC2 Instance {instance.id} is older than {max_ec2_instance_age_in_days} days ({time_since_launch.days} days)."

            findings.append(report)

        return findings
