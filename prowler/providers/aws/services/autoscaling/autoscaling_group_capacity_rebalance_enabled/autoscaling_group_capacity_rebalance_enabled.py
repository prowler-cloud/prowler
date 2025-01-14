from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_capacity_rebalance_enabled(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            if group.load_balancers and group.target_groups:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=group
                )
                report.resource_id = group.name
                report.status = "FAIL"
                report.status_extended = f"Autoscaling group {group.name} does not have capacity rebalance enabled."
                if group.capacity_rebalance:
                    report.status = "PASS"
                    report.status_extended = f"Autoscaling group {group.name} has capacity rebalance enabled."

                findings.append(report)

        return findings
