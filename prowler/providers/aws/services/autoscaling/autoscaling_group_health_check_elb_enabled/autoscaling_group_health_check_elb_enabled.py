from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_health_check_elb_enabled(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            report = Check_Report_AWS(self.metadata())
            report.region = group.region
            report.resource_id = group.name
            report.resource_arn = group.arn
            report.resource_tags = group.tags
            report.status = "FAIL"
            report.status_extended = f"Autoscaling group {group.name} does not have health check ELB enabled."
            if "ELB" in group.health_check_type:
                report.status = "PASS"
                report.status_extended = (
                    f"Autoscaling group {group.name} has health check ELB enabled."
                )

            findings.append(report)

        return findings
