from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_char_combination(Check):
    """Check if Huawei Cloud IAM password policy requires at least 3 character types."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if iam_client.password_policy:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=iam_client.password_policy
            )
            report.region = iam_client.region
            report.resource_id = f"{iam_client.audited_account}-password-policy"
            report.resource_name = report.resource_id
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:password-policy"
            )

            if iam_client.password_policy.password_char_combination >= 3:
                report.status = "PASS"
                report.status_extended = f"IAM password policy requires at least {iam_client.password_policy.password_char_combination} character types in passwords."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM password policy only requires {iam_client.password_policy.password_char_combination} character type(s), which is less than the recommended 3 (uppercase, lowercase, digits, special characters)."

            findings.append(report)

        return findings
