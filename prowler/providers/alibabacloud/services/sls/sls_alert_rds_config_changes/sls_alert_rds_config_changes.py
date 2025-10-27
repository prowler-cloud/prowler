from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.lib.check.check_utils import (
    GenericAlibabaCloudResource,
)
from prowler.providers.alibabacloud.services.sls.sls_client import sls_client


class sls_alert_rds_config_changes(Check):
    def execute(self):
        findings = []
        rds_config_alerts = []
        for alert in sls_client.alerts.values():
            if (
                "rds" in alert.display_name.lower()
                and "config" in alert.display_name.lower()
            ):
                if alert.state == "Enabled":
                    rds_config_alerts.append(alert)
        resource = GenericAlibabaCloudResource(
            id="sls-alerts",
            name="SLS Alert Configuration",
            arn=f"acs:sls::{sls_client.account_id}:alerts",
            region="global",
        )
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=resource)
        report.status = "FAIL"
        report.status_extended = (
            "No enabled alerts found for monitoring RDS configuration changes."
        )
        if len(rds_config_alerts) > 0:
            alert_names = [alert.display_name for alert in rds_config_alerts]
            report.status = "PASS"
            report.status_extended = f"Found {len(rds_config_alerts)} enabled alert(s) monitoring RDS configuration changes: {', '.join(alert_names)}."
        findings.append(report)
        return findings
