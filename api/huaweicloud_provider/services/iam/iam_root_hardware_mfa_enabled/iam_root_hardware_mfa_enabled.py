from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    """Check if Huawei Cloud root account has MFA enabled."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        root_user = None
        for user in iam_client.users:
            if user.is_domain_owner:
                root_user = user
                break

        if root_user:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(), resource=root_user
            )
            report.region = iam_client.region
            report.resource_id = root_user.id
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:root-mfa"
            )

            root_mfa_devices = [
                device
                for device in iam_client.mfa_devices
                if device.user_id == root_user.id
            ]

            if root_mfa_devices:
                report.status = "PASS"
                report.status_extended = "Root account has MFA enabled."
            else:
                report.status = "FAIL"
                report.status_extended = "Root account does not have MFA enabled."

            findings.append(report)

        return findings
