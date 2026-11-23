from collections import Counter

from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_user_multiple_access_keys(Check):
    """Check if IAM users have at most one active permanent access key."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        active_counts = Counter(
            key.user_id
            for key in iam_client.access_keys
            if key.status.lower() == "active" and key.user_id
        )

        for user in iam_client.users:
            count = active_counts.get(user.id, 0)
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=user)
            report.region = iam_client.region
            report.resource_id = user.id
            report.resource_name = user.name
            report.resource_arn = (
                f"huaweicloud:iam::{iam_client.audited_account}:user/{user.id}"
            )

            if count > 1:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM user {user.name} ({user.id}) has {count} active access keys."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM user {user.name} ({user.id}) "
                    f"does not have multiple active access keys."
                )

            findings.append(report)

        return findings
