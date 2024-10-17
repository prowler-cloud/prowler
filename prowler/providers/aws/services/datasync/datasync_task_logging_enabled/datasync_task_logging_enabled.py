from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.datasync.datasync_client import datasync_client


class datasync_task_logging_enabled(Check):
    """Check if AWS DataSync tasks have logging enabled.

    This class verifies whether each AWS DataSync task has logging enabled by checking
    for the presence of a CloudWatch Log Group ARN in the task's configuration.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the DataSync tasks logging enabled check.

        Iterates over all DataSync tasks and generates a report indicating whether
        each task has logging enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for task in datasync_client.tasks.values():
            report = Check_Report_AWS(self.metadata())
            report.region = task.region
            report.resource_id = task.id
            report.resource_arn = task.arn
            report.resource_tags = task.tags
            report.status = "PASS"
            report.status_extended = f"DataSync task {task.name} has logging enabled."

            if not task.cloudwatch_log_group_arn:
                report.status = "FAIL"
                report.status_extended = (
                    f"DataSync task {task.name} does not have logging enabled."
                )

            findings.append(report)
        return findings
