from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_object_lock(Check):
    """Check if OBS buckets have Object Lock (WORM) enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            if bucket.object_lock_enabled is None:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"

            if bucket.object_lock_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} has Object Lock enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"OBS bucket {bucket.name} does not have Object Lock enabled."
                )

            findings.append(report)

        return findings
