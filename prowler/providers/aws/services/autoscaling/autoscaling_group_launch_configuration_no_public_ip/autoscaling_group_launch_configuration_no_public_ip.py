from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_launch_configuration_no_public_ip(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            for lc in autoscaling_client.launch_configurations.values():
                if lc.name == group.launch_configuration_name:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource_metadata=group
                    )
                    report.resource_id = group.name
                    report.status = "PASS"
                    report.status_extended = f"Autoscaling group {group.name} does not have an associated launch configuration assigning a public IP address."

                    if lc.public_ip:
                        report.status = "FAIL"
                        report.status_extended = f"Autoscaling group {group.name} has an associated launch configuration assigning a public IP address."

                    findings.append(report)

        return findings
