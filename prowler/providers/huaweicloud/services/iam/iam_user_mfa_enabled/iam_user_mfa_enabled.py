from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_user_mfa_enabled(Check):
    """Check if Huawei Cloud IAM users have MFA enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for user in iam_client.users:
            if user.is_domain_owner:
                continue

            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=user)
            report.region = iam_client.region
            report.resource_id = user.id
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:user/{user.id}"
            )

            user_mfa_devices = [
                device for device in iam_client.mfa_devices if device.user_id == user.id
            ]

            if user_mfa_devices:
                report.status = "PASS"
                report.status_extended = f"IAM user {user.name} has MFA enabled."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM user {user.name} does not have MFA enabled."
                )

            findings.append(report)

        return findings
