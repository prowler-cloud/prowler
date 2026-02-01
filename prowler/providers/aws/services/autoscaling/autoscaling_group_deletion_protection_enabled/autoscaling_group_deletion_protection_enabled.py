from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_deletion_protection_enabled(Check):
    def execute(self):
        findings = []
        for group in autoscaling_client.groups:
            report = Check_Report_AWS(metadata=self.metadata(), resource=group)

            if group.deletion_protection == "none":
                report.status = "FAIL"
                report.status_extended = f"Autoscaling group {group.name} does not have deletion protection enabled."
            else:
                report.status = "PASS"
                report.status_extended = f"Autoscaling group {group.name} has deletion protection set to {group.deletion_protection}."

            findings.append(report)

        return findings
