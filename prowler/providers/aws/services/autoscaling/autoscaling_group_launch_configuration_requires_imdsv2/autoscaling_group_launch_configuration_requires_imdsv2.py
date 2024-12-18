from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_launch_configuration_requires_imdsv2(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            for (
                launch_configuration
            ) in autoscaling_client.launch_configurations.values():
                if launch_configuration.name == group.launch_configuration_name:
                    report = Check_Report_AWS(self.metadata())
                    report.region = group.region
                    report.resource_id = group.name
                    report.resource_arn = group.arn
                    report.resource_tags = group.tags
                    report.status = "FAIL"
                    report.status_extended = f"Autoscaling group {group.name} has IMDSv2 disabled or not required."
                    if (
                        launch_configuration.http_endpoint == "enabled"
                        and launch_configuration.http_tokens == "required"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Autoscaling group {group.name} has IMDSv2 enabled and required."
                    elif launch_configuration.http_endpoint == "disabled":
                        report.status = "PASS"
                        report.status_extended = f"Autoscaling group {group.name} has metadata service disabled."

                    findings.append(report)

        return findings
