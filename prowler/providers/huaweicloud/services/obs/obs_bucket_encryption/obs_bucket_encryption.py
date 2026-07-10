from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_encryption(Check):
    """Check if OBS buckets have encryption enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=bucket
            )
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = (
                f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"
            )

            if bucket.is_encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} has server-side encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"OBS bucket {bucket.name} does not have server-side encryption enabled."
                )

            findings.append(report)

        return findings
