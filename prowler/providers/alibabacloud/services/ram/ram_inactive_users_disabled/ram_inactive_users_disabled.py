"""
Check: ram_inactive_users_disabled

Ensures that inactive RAM users are disabled or removed.
Inactive accounts pose a security risk as they may be forgotten and have outdated permissions.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from datetime import datetime, timedelta
from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_inactive_users_disabled(Check):
    """Check if inactive RAM users (90+ days without login) are disabled"""

    def execute(self):
        """Execute the ram_inactive_users_disabled check"""
        findings = []

        for user_arn, user in ram_client.users.items():
            report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=user)
            report.account_uid = ram_client.account_id
            report.region = "global"
            report.resource_id = user.id
            report.resource_arn = user.arn

            # Check if user has console login enabled
            if user.console_login_enabled and user.last_login_date:
                try:
                    last_login = datetime.fromisoformat(user.last_login_date.replace('Z', '+00:00'))
                    days_inactive = (datetime.now(last_login.tzinfo) - last_login).days

                    if days_inactive <= 90:
                        report.status = "PASS"
                        report.status_extended = f"RAM user {user.name} was last active {days_inactive} days ago (within 90-day threshold)."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"RAM user {user.name} has been inactive for {days_inactive} days. Disable or remove inactive users."
                except Exception:
                    report.status = "FAIL"
                    report.status_extended = f"Unable to determine last login date for RAM user {user.name}. Review user activity."
            elif user.console_login_enabled:
                report.status = "FAIL"
                report.status_extended = f"RAM user {user.name} has console access but no recorded login. Review if user is needed."
            else:
                report.status = "PASS"
                report.status_extended = f"RAM user {user.name} does not have console login enabled."

            findings.append(report)

        return findings
