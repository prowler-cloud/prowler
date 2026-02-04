from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.autoscaling.autoscaling_client import (
    autoscaling_client,
)


class autoscaling_group_deletion_protection_enabled(Check):
    """
    Auto Scaling groups should have deletion protection enabled to prevent accidental or unauthorized deletion.
    This check verifies if Auto Scaling groups have deletion protection configured.
    AWS ASGs support three levels of deletion protection: 'none', 'prevent-force-deletion', and 'prevent-all-deletion'.
    If deletion protection is set to 'none', it will be marked as FAIL.
    If deletion protection is set to 'prevent-force-deletion' or 'prevent-all-deletion', it will be marked as PASS.
    """

    def execute(self):
        """
        Execute the Auto Scaling group deletion protection check.

        Iterate over all Auto Scaling groups and check if deletion protection is enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
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
