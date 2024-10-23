from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_security_trail_enabled(Check):
    def execute(self):
        findings = []

        if cloudtrail_client.trails:
            for trail in cloudtrail_client.trails.values():
                if trail.name:
                    report = Check_Report_AWS(self.metadata())
                    report.region = trail.region
                    report.resource_id = trail.name
                    report.resource_arn = trail.arn
                    report.resource_tags = trail.tags
                    report.status = "PASS"
                    report.status_extended = f"CloudTrail {trail.name} is configured with security best practices."

                    # Check if the trail records global service events
                    if (
                        not trail.is_multiregion
                    ):  # is_multiregion typically implies global service event recording
                        report.status = "FAIL"
                        report.status_extended = f"CloudTrail {trail.name} does not record global service events."

                    # Check if the trail is multi-region
                    if not trail.is_multiregion:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"CloudTrail {trail.name} is not a multi-region trail."
                        )

                    # Check if log file validation is enabled
                    if not trail.log_file_validation_enabled:
                        report.status = "FAIL"
                        report.status_extended = f"CloudTrail {trail.name} does not have log file validation enabled."

                    # Check if the trail is encrypted with a KMS key
                    if not trail.kms_key:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"CloudTrail {trail.name} is not encrypted with a KMS key."
                        )

                    # Check if the trail records events for reads and writes
                    records_read_write_events = any(
                        selector.event_selector.get("ReadWriteType")
                        in ["All", "ReadOnly", "WriteOnly"]
                        for selector in trail.data_events
                    )
                    if not records_read_write_events:
                        report.status = "FAIL"
                        report.status_extended = f"CloudTrail {trail.name} does not record events for reads and writes."

                    # Check if the trail records management events
                    records_management_events = any(
                        selector.event_selector.get("IncludeManagementEvents", False)
                        for selector in trail.data_events
                    )
                    if not records_management_events:
                        report.status = "FAIL"
                        report.status_extended = f"CloudTrail {trail.name} does not record management events."

                    # Check if the trail excludes any management events
                    excludes_management_events = any(
                        selector.event_selector.get("ExcludeManagementEventSources")
                        for selector in trail.data_events
                    )
                    if excludes_management_events:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"CloudTrail {trail.name} excludes some management events."
                        )

                    findings.append(report)

        # If no trails meet all criteria, mark as NON_COMPLIANT
        if not any(finding.status == "PASS" for finding in findings):
            overall_report = Check_Report_AWS(self.metadata())
            overall_report.status = "FAIL"
            overall_report.status_extended = (
                "No CloudTrail trail meets all security best practices."
            )
            findings.append(overall_report)

        return findings
