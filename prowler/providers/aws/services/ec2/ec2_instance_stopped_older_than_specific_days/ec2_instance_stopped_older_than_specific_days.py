from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_stopped_older_than_specific_days(Check):
    """Check if stopped EC2 instances were launched more than the configured number of days ago."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the EC2 stopped instance launch-age check.

        Flags instances that were launched more than N days ago and are
        currently in the ``stopped`` state.

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
                days_since_launch = (
                    datetime.now(timezone.utc) - instance.launch_time
                ).days
                if days_since_launch > max_ec2_stopped_instance_age_in_days:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"EC2 Instance {instance.id} was launched {days_since_launch} days ago and is currently stopped."
                    )
                else:
                    report.status_extended = (
                        f"EC2 Instance {instance.id} was launched {days_since_launch} days ago and is currently stopped, which is within the {max_ec2_stopped_instance_age_in_days}-day threshold."
                    )

            findings.append(report)

        return findings
