from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_launch_config_public_ip_disabled(Check):
    def execute(self):
        findings = []

        for lc in autoscaling_client.launch_configurations:
            report = Check_Report_AWS(self.metadata())
            report.region = lc.region
            report.resource_id = lc.name
            report.resource_arn = lc.arn
            report.resource_tags = lc.tags

            if lc.associate_public_ip_address:
                report.status = "FAIL"
                report.status_extended = f"Auto Scaling launch configuration {lc.name} has public IP enabled."
            else:
                report.status = "PASS"
                report.status_extended = f"Auto Scaling launch configuration {lc.name} does not have public IP enabled."

            findings.append(report)

        return findings
