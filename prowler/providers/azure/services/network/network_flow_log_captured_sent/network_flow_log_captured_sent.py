from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_flow_log_captured_sent(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            for network_watcher in network_watchers:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=network_watcher
                )
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has no flow logs"
                if network_watcher.flow_logs:
                    has_enabled_flow_logs = any(
                        flow_log.enabled for flow_log in network_watcher.flow_logs
                    )
                    has_workspace_backed_flow_logs = any(
                        flow_log.enabled
                        and flow_log.traffic_analytics_enabled
                        and flow_log.workspace_resource_id
                        for flow_log in network_watcher.flow_logs
                    )

                    if has_workspace_backed_flow_logs:
                        report.status = "PASS"
                        report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs that are captured and sent to Log Analytics workspace"
                    elif has_enabled_flow_logs:
                        report.status = "FAIL"
                        report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has enabled flow logs that are not configured to send traffic analytics to a Log Analytics workspace"
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs disabled"

                findings.append(report)

        return findings
