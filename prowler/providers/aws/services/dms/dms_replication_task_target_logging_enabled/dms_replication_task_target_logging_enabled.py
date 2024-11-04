from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client


class dms_replication_task_source_logging_enabled(Check):
    """
    Check if AWS DMS Endpoints for Neptune have IAM authorization enabled.
    This class verifies whether each AWS DMS Endpoint configured for Neptune has IAM authorization enabled
    by checking the `NeptuneSettings.IamAuthEnabled` property in the endpoint's configuration.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the DMS Neptune IAM authorization enabled check.
        Iterates over all DMS Endpoints and generates a report indicating whether
        each Neptune endpoint has IAM authorization enabled.
        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
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
                report.status_extended = f"DMS Replication Task {replication_task.id} does not have logging enabled."
            else:
                missing_components = []
                source_capture_compliant = False
                source_unload_compliant = False

                for component in replication_task.log_components:
                    if component["Id"] == "SOURCE_CAPTURE" and component[
                        "Severity"
                    ] in [
                        "LOGGER_SEVERITY_DEFAULT",
                        "LOGGER_SEVERITY_DEBUG",
                        "LOGGER_SEVERITY_DETAILED_DEBUG",
                    ]:
                        source_capture_compliant = True
                    elif component["Id"] == "SOURCE_UNLOAD" and component[
                        "Severity"
                    ] in [
                        "LOGGER_SEVERITY_DEFAULT",
                        "LOGGER_SEVERITY_DEBUG",
                        "LOGGER_SEVERITY_DETAILED_DEBUG",
                    ]:
                        source_unload_compliant = True

                if not source_capture_compliant:
                    missing_components.append("SOURCE_CAPTURE")
                if not source_unload_compliant:
                    missing_components.append("SOURCE_UNLOAD")

                if source_capture_compliant and source_unload_compliant:
                    report.status = "PASS"
                    report.status_extended = (
                        f"DMS Replication Task {replication_task.id} has logging enabled with "
                        f"required levels for SOURCE_CAPTURE and SOURCE_UNLOAD components."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"DMS Replication Task {replication_task.id} does not meet logging requirements. "
                        f"Missing or non-compliant components: {', '.join(missing_components)}."
                    )

            findings.append(report)

        return findings
