from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_enabled(Check):
    """Check if CTS tracker is enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if not cts_client.trackers:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
            report.region = cts_client.region
            report.resource_id = f"{cts_client.audited_account}-cts-tracker"
            report.resource_arn = (
                f"HUAWEICLOUD::CTS::{cts_client.audited_account}:tracker"
            )
            report.status = "FAIL"
            report.status_extended = (
                "No CTS tracker found. Cloud Trace Service is not enabled."
            )
            findings.append(report)
        else:
            for tracker in cts_client.trackers:
                report = CheckReportHuaweiCloud(
                    metadata=self.metadata(), resource=tracker
                )
                report.region = tracker.region
                report.resource_id = tracker.id
                report.resource_arn = f"huaweicloud:cts:{tracker.region}:{cts_client.audited_account}:tracker/{tracker.id}"

                if tracker.is_enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"CTS tracker {tracker.name} ({tracker.id}) is enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CTS tracker {tracker.name} ({tracker.id}) is not enabled."
                    )

                findings.append(report)

        return findings
