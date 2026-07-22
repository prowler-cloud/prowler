from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_expires_passwords(Check):
    """Check if Huawei Cloud IAM password policy requires passwords to expire."""

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

            if iam_client.password_policy.password_validity_period > 0:
                report.status = "PASS"
                report.status_extended = f"IAM password policy requires passwords to expire after {iam_client.password_policy.password_validity_period} days."
            else:
                report.status = "FAIL"
                report.status_extended = "IAM password policy does not require passwords to expire (password_validity_period is 0)."

            findings.append(report)

        return findings
