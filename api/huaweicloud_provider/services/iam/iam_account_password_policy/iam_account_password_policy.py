from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_account_password_policy(Check):
    """Check if Huawei Cloud IAM password policy requires minimum length of 14 or greater."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        if iam_client.password_policy:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=iam_client.password_policy
            )
            report.region = iam_client.region
            report.resource_id = f"{iam_client.audited_account}-password-policy"
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:password-policy"
            )

            if iam_client.password_policy.minimum_password_length >= 14:
                report.status = "PASS"
                report.status_extended = f"IAM password policy requires minimum length of {iam_client.password_policy.minimum_password_length} characters."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM password policy requires minimum length of {iam_client.password_policy.minimum_password_length} characters, which is less than the recommended 14 characters."

            findings.append(report)

        return findings
