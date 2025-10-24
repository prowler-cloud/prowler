"""
Check: sls_alert_root_account_logins

Ensures that an alert is configured to monitor root account logins.
Root account usage should be monitored as it has unrestricted access to all resources.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_root_account_logins(Check):
    """Check if an alert is configured for root account logins"""

    def execute(self):
        """Execute the sls_alert_root_account_logins check"""
        findings = []

        # Check if there's at least one alert monitoring root account logins
        root_login_alerts = []
        for alert_arn, alert in sls_client.alerts.items():
            # Check if alert monitors root account logins based on name or configuration
            if "root" in alert.display_name.lower() and "login" in alert.display_name.lower():
                if alert.state == "Enabled":
                    root_login_alerts.append(alert)

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

        if len(root_login_alerts) > 0:
            alert_names = [alert.display_name for alert in root_login_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(root_login_alerts)} enabled alert(s) monitoring root account logins: {', '.join(alert_names)}."
        else:
            report.status = "FAIL"
            report.status_extended = "No enabled alerts found for monitoring root account logins. Create and enable an alert to detect root account usage."

        findings.append(report)
        return findings
