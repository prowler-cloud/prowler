from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_minimum_age(Check):
    """Check if Huawei Cloud IAM password policy enforces a minimum password age."""

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

            if iam_client.password_policy.minimum_password_age > 0:
                report.status = "PASS"
                report.status_extended = f"IAM password policy enforces a minimum password age of {iam_client.password_policy.minimum_password_age} days."
            else:
                report.status = "FAIL"
                report.status_extended = "IAM password policy does not enforce a minimum password age (minimum_password_age is 0), allowing users to change passwords immediately and bypass reuse prevention."

            findings.append(report)

        return findings
