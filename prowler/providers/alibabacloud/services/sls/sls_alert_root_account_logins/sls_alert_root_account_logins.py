from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_root_account_logins(Check):
    def execute(self):
        findings = []
        root_login_alerts = []
        for alert in sls_client.alerts.values():
            if (
                "root" in alert.display_name.lower()
                and "login" in alert.display_name.lower()
            ):
                if alert.state == "Enabled":
                    root_login_alerts.append(alert)
        resource = GenericAlibabaCloudResource(
            id="sls-alerts",
            name="SLS Alert Configuration",
            arn=f"acs:sls::{sls_client.account_id}:alerts",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = (
            "No enabled alerts found for monitoring root account logins."
        )
        if len(root_login_alerts) > 0:
            alert_names = [alert.display_name for alert in root_login_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(root_login_alerts)} enabled alert(s) monitoring root account logins: {', '.join(alert_names)}."
        findings.append(report)
        return findings
