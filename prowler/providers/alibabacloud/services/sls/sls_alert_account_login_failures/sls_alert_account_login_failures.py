from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_account_login_failures(Check):
    def execute(self):
        findings = []
        login_failure_alerts = []
        for alert in sls_client.alerts.values():
            if (
                "login" in alert.display_name.lower()
                and "failure" in alert.display_name.lower()
            ) or (
                "login" in alert.display_name.lower()
                and "fail" in alert.display_name.lower()
            ):
                if alert.state == "Enabled":
                    login_failure_alerts.append(alert)
        resource = GenericAlibabaCloudResource(
            id="sls-alerts",
            name="SLS Alert Configuration",
            arn=f"acs:sls::{sls_client.account_id}:alerts",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = (
            "No enabled alerts found for monitoring account login failures."
        )
        if len(login_failure_alerts) > 0:
            alert_names = [alert.display_name for alert in login_failure_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(login_failure_alerts)} enabled alert(s) monitoring account login failures: {', '.join(alert_names)}."
        findings.append(report)
        return findings
