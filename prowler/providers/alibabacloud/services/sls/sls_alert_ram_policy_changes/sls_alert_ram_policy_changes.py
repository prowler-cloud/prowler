from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_ram_policy_changes(Check):
    def execute(self):
        findings = []
        ram_policy_alerts = []
        for alert in sls_client.alerts.values():
            if (
                "ram" in alert.display_name.lower()
                and "policy" in alert.display_name.lower()
            ):
                if alert.state == "Enabled":
                    ram_policy_alerts.append(alert)
        resource = GenericAlibabaCloudResource(
            id="sls-alerts",
            name="SLS Alert Configuration",
            arn=f"acs:sls::{sls_client.account_id}:alerts",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = (
            "No enabled alerts found for monitoring RAM policy changes."
        )
        if len(ram_policy_alerts) > 0:
            alert_names = [alert.display_name for alert in ram_policy_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(ram_policy_alerts)} enabled alert(s) monitoring RAM policy changes: {', '.join(alert_names)}."
        findings.append(report)
        return findings
