"""
Check: sls_alert_account_login_failures

Ensures that an alert is configured to monitor account login failures.
Monitoring login failures helps detect brute force attacks and unauthorized access attempts.

Risk Level: MEDIUM
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_account_login_failures(Check):
    """Check if an alert is configured for account login failures"""

    def execute(self):
        """Execute the sls_alert_account_login_failures check"""
        findings = []

        # Check if there's at least one alert monitoring login failures
        login_failure_alerts = []
        for alert_arn, alert in sls_client.alerts.items():
            if ("login" in alert.display_name.lower() and "failure" in alert.display_name.lower()) or \
               ("account" in alert.display_name.lower() and "login" in alert.display_name.lower() and "failure" in alert.display_name.lower()):
                if alert.state == "Enabled":
                    login_failure_alerts.append(alert)

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

        if len(login_failure_alerts) > 0:
            alert_names = [alert.display_name for alert in login_failure_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(login_failure_alerts)} enabled alert(s) monitoring account login failures: {', '.join(alert_names)}."
        else:
            report.status = "FAIL"
            report.status_extended = "No enabled alerts found for monitoring account login failures. Create and enable an alert to detect potential brute force attacks."

        findings.append(report)
        return findings
