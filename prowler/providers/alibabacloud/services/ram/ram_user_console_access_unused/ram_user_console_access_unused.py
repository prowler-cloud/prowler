import datetime

from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_user_console_access_unused(Check):
    """Check if RAM users with console access have logged in within the configured days."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        maximum_unused_days = ram_client.audit_config.get("max_console_access_days", 90)
        findings = []
        for user in ram_client.users:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=user)
            report.region = ram_client.region
            report.resource_id = user.name
            report.resource_arn = (
                f"acs:ram::{ram_client.audited_account}:user/{user.name}"
            )
            if user.has_console_access:
                if user.password_last_used:
                    time_since_insertion = (
                        datetime.datetime.now()
                        - datetime.datetime.strptime(
                            str(user.password_last_used), "%Y-%m-%d %H:%M:%S+00:00"
                        )
                    )
                    if time_since_insertion.days > maximum_unused_days:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"RAM user {user.name} has not logged in to the console "
                            f"in the past {maximum_unused_days} days "
                            f"({time_since_insertion.days} days)."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"RAM user {user.name} has logged in to the console "
                            f"in the past {maximum_unused_days} days "
                            f"({time_since_insertion.days} days)."
                        )
                else:
                    # User has console access but has never logged in
                    report.status = "FAIL"
                    report.status_extended = (
                        f"RAM user {user.name} has console access enabled "
                        "but has never logged in to the console."
                    )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"RAM user {user.name} does not have console access enabled."
                )

            findings.append(report)
        return findings
