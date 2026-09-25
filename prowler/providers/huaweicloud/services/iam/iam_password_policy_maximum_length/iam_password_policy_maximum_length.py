from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_maximum_length(Check):
    """Check if Huawei Cloud IAM password policy maximum length is set to 32 or greater."""

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

            if iam_client.password_policy.maximum_password_length >= 32:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM password policy allows maximum password length of "
                    f"{iam_client.password_policy.maximum_password_length} characters."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM password policy allows maximum password length of "
                    f"{iam_client.password_policy.maximum_password_length} characters, "
                    f"which is less than the recommended 32 characters."
                )

            findings.append(report)

        return findings
