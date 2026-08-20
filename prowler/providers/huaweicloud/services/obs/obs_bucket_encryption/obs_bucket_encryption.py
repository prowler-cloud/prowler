from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.obs.obs_client import obs_client


class obs_bucket_encryption(Check):
    """Check if OBS buckets have encryption enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        """Return one finding for each discovered OBS bucket.

        Returns:
            A list of reports describing each bucket's encryption status.
        """
        findings = []

        for bucket in obs_client.buckets:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=bucket)
            report.region = bucket.region
            report.resource_arn = (
                bucket.arn
                or f"huaweicloud:obs:{bucket.region}:{obs_client.audited_account}:bucket/{bucket.name}"
            )

            if bucket.is_encrypted is True:
                report.status = "PASS"
                report.status_extended = f"OBS bucket {bucket.name} has {bucket.encryption} server-side encryption enabled."
            elif bucket.is_encrypted is False:
                report.status = "FAIL"
                report.status_extended = f"OBS bucket {bucket.name} does not have default server-side encryption enabled."
            else:
                report.status = "MANUAL"
                report.status_extended = f"OBS bucket {bucket.name} encryption configuration could not be determined: {bucket.encryption_error}"

            findings.append(report)

        return findings
