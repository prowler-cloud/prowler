from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_multiple_instance_types(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = group.region
            report.resource_id = group.name
            report.resource_arn = group.arn
            report.resource_tags = group.tags
            report.status = "FAIL"
            report.status_extended = f"Autoscaling group {group.name} does not have multiple instance types in multiple Availability Zones."

            failing_azs = []

            for az, types in group.az_instance_types.items():
                if len(types) < 2:
                    failing_azs.append(az)

            if not failing_azs and len(group.az_instance_types) > 1:
                report.status = "PASS"
                report.status_extended = f"Autoscaling group {group.name} has multiple instance types in each of its Availability Zones."
            elif failing_azs:
                azs_str = ", ".join(failing_azs)
                report.status_extended = f"Autoscaling group {group.name} has only one or no instance types in Availability Zone(s): {azs_str}."

            findings.append(report)

        return findings
