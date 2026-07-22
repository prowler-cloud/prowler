from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_stopped_older_than_specific_days(Check):
    """Check if EC2 instances have been stopped for longer than the configured maximum age."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the EC2 stopped instance age check.

        Returns:
            list[Check_Report_AWS]: List of findings for each EC2 instance.
        """
        findings = []

        max_ec2_stopped_instance_age_in_days = ec2_client.audit_config.get(
            "max_ec2_stopped_instance_age_in_days", 30
        )
        for instance in ec2_client.instances:
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = f"EC2 Instance {instance.id} is not stopped."
            if instance.state == "stopped":
                # Calculate time since launch (used as proxy for stopped duration)
                # Note: AWS API does not provide a direct state transition timestamp
                time_since_launch = (
                    datetime.now(timezone.utc) - instance.launch_time
                )
                report.status_extended = f"EC2 Instance {instance.id} is stopped for {time_since_launch.days} days, which is not older than {max_ec2_stopped_instance_age_in_days} days."
                if time_since_launch.days > max_ec2_stopped_instance_age_in_days:
                    report.status = "FAIL"
                    report.status_extended = f"EC2 Instance {instance.id} is stopped for {time_since_launch.days} days, which is older than {max_ec2_stopped_instance_age_in_days} days."

            findings.append(report)

        return findings
