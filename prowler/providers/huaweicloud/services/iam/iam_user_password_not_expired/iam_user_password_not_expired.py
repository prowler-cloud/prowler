from datetime import datetime, timezone

from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.iam.iam_client import iam_client


class iam_user_password_not_expired(Check):
    """Check if Huawei Cloud IAM users do not have expired passwords."""

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

            if user.password_expires_at is None:
                report.status = "PASS"
                report.status_extended = (
                    f"IAM user {user.name} has no password expiration configured."
                )
            else:
                try:
                    expires_at = datetime.fromisoformat(
                        user.password_expires_at.replace("Z", "+00:00")
                    )
                    now = datetime.now(timezone.utc)

                    if expires_at > now:
                        report.status = "PASS"
                        report.status_extended = (
                            f"IAM user {user.name} password expires at "
                            f"{user.password_expires_at}."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"IAM user {user.name} password expired at "
                            f"{user.password_expires_at}."
                        )
                except (ValueError, AttributeError):
                    report.status = "PASS"
                    report.status_extended = (
                        f"IAM user {user.name} has password expiration set to "
                        f"{user.password_expires_at}."
                    )

            findings.append(report)

        return findings
