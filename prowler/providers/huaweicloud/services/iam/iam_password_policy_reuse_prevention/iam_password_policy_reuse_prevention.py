from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_password_policy_reuse_prevention(Check):
    """Check if Huawei Cloud IAM password policy prevents password reuse (at least 3 previous passwords)."""

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

            if iam_client.password_policy.number_of_recent_passwords_disallowed >= 3:
                report.status = "PASS"
                report.status_extended = f"IAM password policy disallows reuse of the last {iam_client.password_policy.number_of_recent_passwords_disallowed} passwords."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM password policy only disallows reuse of the last {iam_client.password_policy.number_of_recent_passwords_disallowed} passwords, which is less than the recommended 3."

            findings.append(report)

        return findings
