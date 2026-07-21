from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_public_access(Check):
    """Check if OBS buckets are not publicly accessible."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"

            if bucket.is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"OBS bucket {bucket.name} is publicly accessible."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} is not publicly accessible."
                )

            findings.append(report)

        return findings
