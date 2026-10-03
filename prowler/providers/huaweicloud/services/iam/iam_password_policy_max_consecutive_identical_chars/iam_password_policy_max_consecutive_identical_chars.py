from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_max_consecutive_identical_chars(Check):
    """Check if Huawei Cloud IAM password policy limits consecutive identical characters."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if iam_client.password_policy:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=iam_client.password_policy
            )
            report.region = iam_client.region
            report.resource_id = f"{iam_client.audited_account}-password-policy"
            report.resource_name = "password-policy"
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:password-policy"
            )

            if iam_client.password_policy.maximum_consecutive_identical_chars > 0:
                report.status = "PASS"
                report.status_extended = f"IAM password policy limits consecutive identical characters to {iam_client.password_policy.maximum_consecutive_identical_chars}."
            else:
                report.status = "FAIL"
                report.status_extended = "IAM password policy does not limit consecutive identical characters, allowing passwords like 'aaaaaa' which are easier to crack."

            findings.append(report)

        return findings
