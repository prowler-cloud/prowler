from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_not_username(Check):
    """Check if Huawei Cloud IAM password policy prevents using the username in passwords."""

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

            if iam_client.password_policy.password_not_username_or_invert:
                report.status = "PASS"
                report.status_extended = "IAM password policy prevents using the username (or its inversion) in passwords."
            else:
                report.status = "FAIL"
                report.status_extended = "IAM password policy does not prevent using the username (or its inversion) in passwords, increasing the risk of predictable passwords."

            findings.append(report)

        return findings
