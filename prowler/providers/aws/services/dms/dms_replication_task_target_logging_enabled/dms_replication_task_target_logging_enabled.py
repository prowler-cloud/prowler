from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_replication_task_target_logging_enabled(Check):
    """
    Check if AWS DMS replication tasks have logging enabled with the required
    logging components and severity levels.

    This class verifies that each DMS replication task has logging enabled
    and that the components TARGET_APPLY and TARGET_LOAD are configured with
    at least LOGGER_SEVERITY_DEFAULT severity level. If either component is missing
    or does not meet the minimum severity requirement, the check will fail.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the DMS replication task logging requirements check.

        Iterates over all DMS replication tasks and generates a report indicating
        whether each task has logging enabled and meets the logging requirements
        for TARGET_APPLY and TARGET_LOAD components.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        MINIMUM_SEVERITY_LEVELS = [
            "LOGGER_SEVERITY_DEFAULT",
            "LOGGER_SEVERITY_DEBUG",
            "LOGGER_SEVERITY_DETAILED_DEBUG",
        ]
        findings = []
        for (
            replication_task_arn,
            replication_task,
        ) in dms_client.replication_tasks.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = replication_task.id
            report.resource_arn = replication_task_arn
            report.region = replication_task.region
            report.resource_tags = replication_task.tags

            if not replication_task.logging_enabled:
                report.status = "FAIL"
                report.status_extended = f"DMS Replication Task {replication_task.id} does not have logging enabled for target events."
            else:
                missing_components = []
                source_capture_compliant = False
                source_unload_compliant = False

                for component in replication_task.log_components:
                    if (
                        component["Id"] == "TARGET_APPLY"
                        and component["Severity"] in MINIMUM_SEVERITY_LEVELS
                    ):
                        source_capture_compliant = True
                    elif (
                        component["Id"] == "TARGET_LOAD"
                        and component["Severity"] in MINIMUM_SEVERITY_LEVELS
                    ):
                        source_unload_compliant = True

                if not source_capture_compliant:
                    missing_components.append("Target Apply")
                if not source_unload_compliant:
                    missing_components.append("Target Load")

                if source_capture_compliant and source_unload_compliant:
                    report.status = "PASS"
                    report.status_extended = f"DMS Replication Task {replication_task.id} has logging enabled with the minimum severity level in target events."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"DMS Replication Task {replication_task.id} does not meet the minimum severity level of logging in {' and '.join(missing_components)} events."

            findings.append(report)

        return findings
