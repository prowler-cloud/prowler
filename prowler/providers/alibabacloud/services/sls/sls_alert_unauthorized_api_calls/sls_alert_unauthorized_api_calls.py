from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_unauthorized_api_calls(Check):
    def execute(self):
        findings = []
        unauthorized_alerts = []
        for alert in sls_client.alerts.values():
            if (
                "unauthorized" in alert.display_name.lower()
                or "unauthorized" in alert.name.lower()
            ):
                if alert.state == "Enabled":
                    unauthorized_alerts.append(alert)
        resource = GenericAlibabaCloudResource(
            id="sls-alerts",
            name="SLS Alert Configuration",
            arn=f"acs:sls::{sls_client.account_id}:alerts",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = (
            "No enabled alerts found for monitoring unauthorized API calls."
        )
        if len(unauthorized_alerts) > 0:
            alert_names = [alert.display_name for alert in unauthorized_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(unauthorized_alerts)} enabled alert(s) monitoring unauthorized API calls: {', '.join(alert_names)}."
        findings.append(report)
        return findings
