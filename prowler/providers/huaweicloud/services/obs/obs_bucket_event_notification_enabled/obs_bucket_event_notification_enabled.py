from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_event_notification_enabled(Check):
    """Check if OBS buckets have event notifications enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            if bucket.event_notification_enabled is None:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"

            if bucket.event_notification_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} has event notifications enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"OBS bucket {bucket.name} does not have event notifications enabled."

            findings.append(report)

        return findings
