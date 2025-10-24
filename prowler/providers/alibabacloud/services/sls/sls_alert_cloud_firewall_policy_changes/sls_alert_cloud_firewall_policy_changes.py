"""
Check: sls_alert_cloud_firewall_policy_changes

Ensures that an alert is configured in SLS to monitor and notify on Cloud Firewall policy changes.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_cloud_firewall_policy_changes(Check):
    """Check if an alert is configured for cloud firewall policy changes"""

    def execute(self):
        """Execute the sls_alert_cloud_firewall_policy_changes check"""
        findings = []

        # Check if there's at least one alert monitoring cloud firewall policy changes
        matching_alerts = []
        for alert_arn, alert in sls_client.alerts.items():
            if "firewall" in alert.display_name.lower() and "policy" in alert.display_name.lower():
                if alert.state == "Enabled":
                    matching_alerts.append(alert)

        # Create a report for the account
        report = Check_Report_AlibabaCloud(
            metadata=self.metadata(),
            resource=type('obj', (object,), {
                'id': 'sls-alerts',
                'name': 'SLS Alert Configuration',
                'arn': f"acs:sls::{sls_client.account_id}:alerts",
                'region': 'global'
            })()
        )

        report.account_uid = sls_client.account_id
        report.region = "global"
        report.resource_id = "sls-alerts"
        report.resource_arn = f"acs:sls::{sls_client.account_id}:alerts"

        if len(matching_alerts) > 0:
            alert_names = [alert.display_name for alert in matching_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(matching_alerts)} enabled alert(s) monitoring cloud firewall policy changes: {', '.join(alert_names)}."
        else:
            report.status = "FAIL"
            report.status_extended = "No enabled alerts found for monitoring cloud firewall policy changes. Create and enable an alert to detect configuration changes."

        findings.append(report)
        return findings
