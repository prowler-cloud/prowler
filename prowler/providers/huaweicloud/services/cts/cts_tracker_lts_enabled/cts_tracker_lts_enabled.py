from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_tracker_lts_enabled(Check):
    """Check if CTS trackers have LTS log transfer enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for tracker in cts_client.trackers:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=tracker)
            report.region = tracker.region
            report.resource_id = tracker.id
            report.resource_arn = f"huaweicloud:cts:{tracker.region}:{cts_client.audited_account}:tracker/{tracker.id}"

            if tracker.is_lts_enabled:
                report.status = "PASS"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) has LTS log transfer enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) does not have LTS log transfer enabled."

            findings.append(report)

        return findings
