"""
Check: ram_root_usage_minimized

Ensures that root account usage is minimized.
The root account should only be used for account management, not day-to-day operations.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from datetime import datetime

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_root_usage_minimized(Check):
    """Check if root account usage is minimized"""

    def execute(self):
        """Execute the ram_root_usage_minimized check"""
        findings = []

        resource = GenericAlibabaCloudResource(
            id="root-account",
            name="Root Account",
            arn=f"acs:ram::{ram_client.account_id}:root",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)

        report.account_uid = ram_client.account_id
        report.region = "global"
        report.resource_id = "root-account"
        report.resource_arn = f"acs:ram::{ram_client.account_id}:root"

        if ram_client.root_last_activity:
            try:
                last_activity = datetime.fromisoformat(
                    ram_client.root_last_activity.replace("Z", "+00:00")
                )
                days_since_activity = (
                    datetime.now(last_activity.tzinfo) - last_activity
                ).days

                if days_since_activity >= 90:
                    report.status = "PASS"
                    report.status_extended = f"Root account has not been used in the last {days_since_activity} days (inactive for 90+ days)."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Root account was used {days_since_activity} days ago. Minimize root account usage and use RAM users instead."
            except Exception:
                report.status = "FAIL"
                report.status_extended = "Unable to determine root account last activity. Review root account usage."
        else:
            report.status = "PASS"
            report.status_extended = "No recent root account activity detected."

        findings.append(report)
        return findings
