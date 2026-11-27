from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_tracker_obs_encryption_enabled(Check):
    """Check if CTS trackers encrypt trace files stored in OBS."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for tracker in cts_client.trackers:
            if tracker.tracker_type != "system":
                continue
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=tracker)
            report.region = tracker.region
            report.resource_id = tracker.id
            report.resource_arn = f"huaweicloud:cts:{tracker.region}:{cts_client.audited_account}:tracker/{tracker.id}"

            if tracker.is_support_trace_files_encryption:
                report.status = "PASS"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) has OBS trace file encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"CTS tracker {tracker.name} ({tracker.id}) does not have OBS trace file encryption enabled."

            findings.append(report)

        return findings
