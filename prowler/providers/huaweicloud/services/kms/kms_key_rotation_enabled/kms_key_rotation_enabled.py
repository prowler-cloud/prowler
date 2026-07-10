from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.kms.kms_client import kms_client


class kms_key_rotation_enabled(Check):
    """Check if KMS keys have rotation enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for key in kms_client.keys:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=key
            )
            report.region = key.region
            report.resource_id = key.id
            report.resource_arn = (
                f"huaweicloud:kms:{key.region}:{kms_client.audited_account}:key/{key.id}"
            )

            if key.is_rotation_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) has rotation enabled "
                    f"with period {key.rotation_period}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) does not have rotation enabled."
                )

            findings.append(report)

        return findings
