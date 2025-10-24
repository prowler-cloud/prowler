"""
Check: sls_alert_unauthorized_api_calls

Ensures that an alert is configured to monitor unauthorized API calls.
Monitoring unauthorized API calls helps detect potential security breaches or misconfigurations.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_unauthorized_api_calls(Check):
    """Check if an alert is configured for unauthorized API calls"""

    def execute(self):
        """Execute the sls_alert_unauthorized_api_calls check"""
        findings = []

        # Check if there's at least one alert monitoring unauthorized API calls
        unauthorized_alerts = []
        for alert_arn, alert in sls_client.alerts.items():
            # Check if alert monitors unauthorized API calls based on name or configuration
            if "unauthorized" in alert.display_name.lower() or "unauthorized" in alert.name.lower():
                if alert.state == "Enabled":
                    unauthorized_alerts.append(alert)

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

        if len(unauthorized_alerts) > 0:
            alert_names = [alert.display_name for alert in unauthorized_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(unauthorized_alerts)} enabled alert(s) monitoring unauthorized API calls: {', '.join(alert_names)}."
        else:
            report.status = "FAIL"
            report.status_extended = "No enabled alerts found for monitoring unauthorized API calls. Create and enable an alert to detect unauthorized API access attempts."

        findings.append(report)
        return findings
