from datetime import datetime, timezone

from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_user_access_key_rotation_90_days(Check):
    """Check if active IAM user permanent access keys are rotated every 90 days."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        now = datetime.now(timezone.utc)

        for key in iam_client.access_keys:
            if key.status.lower() != "active" or not key.create_time:
                continue

            try:
                created_at = datetime.fromisoformat(
                    key.create_time.replace("Z", "+00:00")
                )
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            age_days = (now - created_at).days
            report = CheckReportHuaweiCloud(metadata=self.metadata(), resource=key)
            report.region = iam_client.region
            report.resource_id = key.access
            report.resource_name = key.access
            report.resource_arn = (
                f"huaweicloud:iam::{iam_client.audited_account}:access-key/{key.access}"
            )

            if age_days <= 90:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM access key {key.access} for user {key.user_id} "
                    f"was rotated within 90 days ({age_days} days old)."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"IAM access key {key.access} for user {key.user_id} "
                    f"has not been rotated for {age_days} days (over 90 days)."
                )

            findings.append(report)

        return findings
