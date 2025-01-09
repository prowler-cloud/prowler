from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_elb_health_check_enabled(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            if group.load_balancers and group.target_groups:
                report = Check_Report_AWS(self.metadata())
                report.region = group.region
                report.resource_id = group.name
                report.resource_arn = group.arn
                report.resource_tags = group.tags
                report.status = "FAIL"
                report.status_extended = f"Autoscaling group {group.name} is associated with a load balancer but does not have ELB health checks enabled, instead it has {group.health_check_type} health checks."
                if "ELB" in group.health_check_type:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Autoscaling group {group.name} has ELB health checks enabled."
                    )

                findings.append(report)

        return findings
