from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_user_disabled(Check):
    """Check if Huawei Cloud IAM has disabled users (stale accounts)."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []

        for user in iam_client.users:
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=user)
            report.region = iam_client.region
            report.resource_id = user.id
            report.resource_arn = (
                f"HUAWEICLOUD::IAM::{iam_client.audited_account}:user/{user.id}"
            )

            if user.enabled:
                report.status = "PASS"
                report.status_extended = f"IAM user {user.name} ({user.id}) is enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"IAM user {user.name} ({user.id}) is disabled and should be reviewed for removal if no longer needed."

            findings.append(report)

        return findings
