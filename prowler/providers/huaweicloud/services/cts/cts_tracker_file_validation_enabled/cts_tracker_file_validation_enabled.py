from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_tracker_file_validation_enabled(Check):
    """Check if CTS trackers have log file integrity validation enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for tracker in cts_client.trackers:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=tracker)
            report.region = tracker.region
            report.resource_id = tracker.id
            report.resource_arn = f"huaweicloud:cts:{tracker.region}:{cts_client.audited_account}:tracker/{tracker.id}"

            if tracker.is_support_validate:
                report.status = "PASS"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) has log file validation enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) does not have log file validation enabled."

            findings.append(report)

        return findings
