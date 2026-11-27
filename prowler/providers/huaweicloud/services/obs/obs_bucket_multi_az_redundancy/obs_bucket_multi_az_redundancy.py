from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_multi_az_redundancy(Check):
    """Check if OBS buckets use multi-AZ (3AZ) redundancy."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for bucket in obs_client.buckets:
            if bucket.az_redundancy is None:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_id = bucket.name
            report.resource_arn = f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"

            if bucket.az_redundancy.lower() == "3az":
                report.status = "PASS"
                report.status_extended = (
                    f"OBS bucket {bucket.name} has multi-AZ (3AZ) redundancy enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"OBS bucket {bucket.name} does not have multi-AZ (3AZ) redundancy enabled."

            findings.append(report)

        return findings
