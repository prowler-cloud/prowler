from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.kms.kms_client import kms_client


class kms_key_rotation_period(Check):
    """Check if KMS keys with rotation enabled have a rotation period configured."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for key in kms_client.keys:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=key)
            report.region = key.region
            report.resource_id = key.id
            report.resource_arn = (
                f"huaweicloud:kms:{key.region}:"
                f"{kms_client.audited_account}:key/{key.id}"
            )

            if not key.is_rotation_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) does not have rotation enabled, "
                    f"rotation period check is not applicable."
                )
            elif key.rotation_period:
                report.status = "PASS"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) has rotation enabled "
                    f"with period {key.rotation_period}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) has rotation enabled "
                    f"but no rotation period is configured."
                )

            findings.append(report)

        return findings
