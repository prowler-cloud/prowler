from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    """Check if the Huawei Cloud account enforces MFA on the root account.

    The account/root (domain owner) is not a listable IAM user in Huawei
    Cloud, so root MFA is assessed through the account's operation protection
    policy, which forces MFA verification for sensitive operations.
    """

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        protection = iam_client.operation_protection

        report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=protection)
        report.region = iam_client.region
        report.resource_id = f"{iam_client.audited_account}-operation-protection"
        report.resource_arn = (
            f"HUAWEICLOUD::IAM::{iam_client.audited_account}:operation-protection"
        )

        if protection.enabled:
            report.status = "PASS"
            report.status_extended = (
                "Root account is protected: account operation protection "
                "(MFA verification for critical operations) is enabled."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Root account is not protected: account operation protection "
                "(MFA verification for critical operations) is not enabled."
            )

        findings.append(report)

        return findings
