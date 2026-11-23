from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_cors_wildcard_origin(Check):
    """Check if OBS buckets do not allow wildcard (*) CORS origin."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            if bucket.cors_allow_origin is None:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"

            if bucket.cors_allow_origin.strip() == "*":
                report.status = "FAIL"
                report.status_extended = (
                    f"OBS bucket {bucket.name} allows wildcard CORS origin (*)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} does not allow wildcard CORS origin."
                )

            findings.append(report)

        return findings
