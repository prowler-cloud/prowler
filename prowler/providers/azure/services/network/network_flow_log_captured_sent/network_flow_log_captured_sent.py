from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_flow_log_captured_sent(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            for network_watcher in network_watchers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = network_watcher.name
                report.resource_id = network_watcher.id
                if network_watcher.flow_logs:
                    report.status = "FAIL"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs disabled"
                    for flow_log in network_watcher.flow_logs:
                        if flow_log.enabled:
                            report.status = "PASS"
                            report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs that are captured and sent to Log Analytics workspace"
                            break
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has no flow logs"
                findings.append(report)

        return findings
