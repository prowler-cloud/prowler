from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_rotate_access_key_90_days(Check):
    """Check if access keys are rotated every 90 days or less."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []
        # Use UTC timezone-aware datetime for consistent comparison
        now = datetime.now(timezone.utc)
        ninety_days_ago = now - timedelta(days=90)

        for user in ram_client.users:
            if user.access_keys:
                for access_key in user.access_keys:
                    # Only check active access keys
                    if access_key.status == "Active":
                        report = CheckReportAlibabaCloud(
                            metadata=self.metadata(), resource=user
                        )
                        report.region = ram_client.region
                        report.resource_id = access_key.access_key_id
                        report.resource_arn = f"acs:ram::{ram_client.audited_account}:user/{user.name}/accesskey/{access_key.access_key_id}"

                        if access_key.create_date:
                            # Ensure create_date is timezone-aware for comparison
                            create_date = access_key.create_date
                            if create_date.tzinfo is None:
                                # If naive, assume UTC
                                create_date = create_date.replace(tzinfo=timezone.utc)

                            if create_date < ninety_days_ago:
                                report.status = "FAIL"
                                days_old = (now - create_date).days
                                report.status_extended = (
                                    f"Access key {access_key.access_key_id} for user {user.name} "
                                    f"has not been rotated in {days_old} days (more than 90 days)."
                                )
                            else:
                                report.status = "PASS"
                                days_old = (now - create_date).days
                                report.status_extended = (
                                    f"Access key {access_key.access_key_id} for user {user.name} "
                                    f"was created {days_old} days ago (within 90 days)."
                                )
                        else:
                            report.status = "PASS"
                            report.status_extended = (
                                f"Access key {access_key.access_key_id} for user {user.name} "
                                f"creation date is not available."
                            )

                        findings.append(report)

        return findings
