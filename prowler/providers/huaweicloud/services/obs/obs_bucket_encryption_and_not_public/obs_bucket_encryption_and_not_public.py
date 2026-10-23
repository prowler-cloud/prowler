from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_encryption_and_not_public(Check):
    """Check if OBS buckets are both encrypted and not publicly accessible."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = (
                f"huaweicloud:obs:{bucket.region}:"
                f"{obs_client.audited_account}:bucket/{bucket.name}"
            )

            if bucket.is_encrypted and not bucket.is_public:
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} is encrypted"
                    f" and not publicly accessible."
                )
            else:
                report.status = "FAIL"
                issues = []
                if not bucket.is_encrypted:
                    issues.append("is not encrypted")
                if bucket.is_public:
                    issues.append("is publicly accessible")
                report.status_extended = (
                    f"OBS bucket {bucket.name} " + " and ".join(issues) + "."
                )

            findings.append(report)

        return findings
