from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_using_ec2_launch_template(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=group)

            report.status = "PASS"
            report.status_extended = (
                f"Autoscaling group {group.name} is using an EC2 launch template."
            )
            if (
                not group.launch_template
                and not group.mixed_instances_policy_launch_template
            ):
                report.status = "FAIL"
                report.status_extended = f"Autoscaling group {group.name} is not using an EC2 launch template."

            findings.append(report)

        return findings
