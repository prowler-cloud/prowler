from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_multiple_instances_types(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = group.region
            report.resource_id = group.name
            report.resource_arn = group.arn
            report.resource_tags = group.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Autoscaling group {group.name} has one or less instance types."
            )
            if len(group.instance_types) > 1:
                if len(group.availability_zones) > 1:
                    report.status = "PASS"
                    report.status_extended = f"Autoscaling group {group.name} has multiple instance types in multiple availability zones."
                else:
                    report.status_extended = f"Autoscaling group {group.name} has multiple instance type in single availability zone."

            findings.append(report)

        return findings
