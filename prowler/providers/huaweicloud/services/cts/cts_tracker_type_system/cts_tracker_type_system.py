from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cts.cts_client import cts_client


class cts_tracker_type_system(Check):
    """Check if CTS has a system-type tracker configured and enabled."""

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
            system_tracker_enabled = False
            for tracker in cts_client.trackers:
                if tracker.tracker_type == "system" and tracker.is_enabled:
                    system_tracker_enabled = True
                    report = CheckReportHuaweiCloud(
                        metadata=self.metadata(), resource=tracker
                    )
                    report.region = tracker.region
                    report.resource_id = tracker.id
                    report.resource_arn = (
                        f"huaweicloud:cts:{tracker.region}:"
                        f"{cts_client.audited_account}:tracker/{tracker.id}"
                    )
                    report.status = "PASS"
                    report.status_extended = (
                        f"CTS system tracker {tracker.name} ({tracker.id}) "
                        f"is configured and enabled."
                    )
                    findings.append(report)

            if not system_tracker_enabled:
                report = CheckReportHuaweiCloud(metadata=self.metadata(), resource={})
                report.region = cts_client.region
                report.resource_id = f"{cts_client.audited_account}-cts-tracker"
                report.resource_name = "cts-tracker"
                report.resource_arn = (
                    f"HUAWEICLOUD::CTS::{cts_client.audited_account}:tracker"
                )
                report.status = "FAIL"
                report.status_extended = (
                    "No enabled system-type CTS tracker found. "
                    "System trackers are required to record all API calls "
                    "and operations across the account."
                )
                findings.append(report)

        return findings
