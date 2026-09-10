from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.kms.kms_client import kms_client


class kms_key_not_pending_deletion(Check):
    """Check if KMS keys are not in pending deletion state."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for key in kms_client.keys:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=key)
            report.region = key.region
            report.resource_id = key.id
            report.resource_arn = f"huaweicloud:kms:{key.region}:{kms_client.audited_account}:key/{key.id}"

            if key.state == "4":
                report.status = "FAIL"
                report.status_extended = (
                    f"KMS key {key.alias} ({key.id}) is in pending deletion state."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"KMS key {key.alias} ({key.id}) is not in pending deletion state (state: {key.state})."

            findings.append(report)

        return findings
