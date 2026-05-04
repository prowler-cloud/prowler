from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_flow_log_captured_sent(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            if network_client.resource_groups:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = subscription
                report.resource_id = (
                    f"/subscriptions/{network_client.subscriptions[subscription]}"
                )
                report.location = "global"
                report.status = "MANUAL"
                report.status_extended = (
                    f"Subscription '{subscription}': flow-log checks require "
                    f"subscription-wide Network Watcher access. Re-run without "
                    f"--azure-resource-group, to evaluate flow log coverage."
                )
                findings.append(report)
                continue

            for network_watcher in network_watchers:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=network_watcher
                )
                report.subscription = subscription
                if network_watcher.flow_logs:
                    report.status = "PASS"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs that are captured and sent to Log Analytics workspace"
                    has_failed = False
                    for flow_log in network_watcher.flow_logs:
                        if not has_failed:
                            if not flow_log.enabled:
                                report.status = "FAIL"
                                report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs disabled"
                                has_failed = True
                            elif not (
                                flow_log.traffic_analytics_enabled
                                and flow_log.workspace_resource_id
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has enabled flow logs that are not configured to send traffic analytics to a Log Analytics workspace"
                                has_failed = True
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has no flow logs"

                findings.append(report)

        return findings
