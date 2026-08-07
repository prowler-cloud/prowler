from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_tracker_bucket_configured(Check):
    """Check if CTS tracker has an OBS bucket configured for trace file delivery."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if not cts_client.trackers:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
            report.region = cts_client.region
            report.resource_id = f"{cts_client.audited_account}-cts-tracker"
            report.resource_name = "cts-tracker"
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
                report.resource_arn = (
                    f"huaweicloud:cts:{tracker.region}:"
                    f"{cts_client.audited_account}:tracker/{tracker.id}"
                )

                if tracker.bucket_name:
                    report.status = "PASS"
                    report.status_extended = (
                        f"CTS tracker {tracker.name} ({tracker.id}) has OBS bucket "
                        f"{tracker.bucket_name} configured for trace file delivery."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CTS tracker {tracker.name} ({tracker.id}) does not have an OBS bucket "
                        f"configured for trace file delivery."
                    )

                findings.append(report)

        return findings
