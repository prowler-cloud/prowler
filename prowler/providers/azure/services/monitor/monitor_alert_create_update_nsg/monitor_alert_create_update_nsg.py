from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitoring_alerts_review.monitoring_alerts_review import (
    check_alerts_review,
)
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_create_update_nsg(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            findings.append(
                check_alerts_review(
                    activity_log_alerts,
                    "Microsoft.Network/networkSecurityGroups/write",
                    self.metadata(),
                    subscription_name,
                )
            )
        return findings
