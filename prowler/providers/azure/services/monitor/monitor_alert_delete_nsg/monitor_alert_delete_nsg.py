from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.lib.monitoring_alerts_review.monitoring_alerts_review import (
    check_alerts_review,
)
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_alert_delete_nsg(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for (
            subscription_name,
            activity_log_alerts,
        ) in monitor_client.alert_rules.items():
            # report = check_alerts_review(activity_log_alerts,"Microsoft.Network/networkSecurityGroups/delete", self.metadata, subscription_name)
            # report_classic = check_alerts_review(activity_log_alerts,"Microsoft.ClassicNetwork/networkSecurityGroups/delete", self.metadata, subscription_name)
            # if report.status == "PASS":
            #    findings.append(report)
            # elif report_classic.status == "PASS":
            #    findings.append(report_classic)
            # else:
            #    findings.append(report)
            if (
                check_alerts_review(
                    activity_log_alerts,
                    "Microsoft.Network/networkSecurityGroups/delete",
                    self.metadata(),
                    subscription_name,
                )
            ).status == "PASS":
                findings.append(
                    check_alerts_review(
                        activity_log_alerts,
                        "Microsoft.Network/networkSecurityGroups/delete",
                        self.metadata(),
                        subscription_name,
                    )
                )
            elif (
                check_alerts_review(
                    activity_log_alerts,
                    "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
                    self.metadata(),
                    subscription_name,
                )
            ).status == "PASS":
                findings.append(
                    check_alerts_review(
                        activity_log_alerts,
                        "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
                        self.metadata(),
                        subscription_name,
                    )
                )
            else:
                findings.append(
                    check_alerts_review(
                        activity_log_alerts,
                        "Microsoft.Network/networkSecurityGroups/delete",
                        self.metadata(),
                        subscription_name,
                    )
                )

        return findings
