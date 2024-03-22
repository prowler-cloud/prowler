from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_flow_log_more_than_90_days(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            for network_watcher in network_watchers:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = network_watcher.name
                report.resource_id = network_watcher.id
                report.location = network_watcher.location
                if network_watcher.flow_logs:
                    report.status = "PASS"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs enabled for more than 90 days"
                    has_failed = False
                    for flow_log in network_watcher.flow_logs:
                        if not has_failed:
                            if not flow_log.enabled:
                                report.status = "FAIL"
                                report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has flow logs disabled"
                                has_failed = True
                            elif flow_log.retention_policy.days < 90 and not has_failed:
                                report.status = "FAIL"
                                report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} flow logs retention policy is less than 90 days"
                                has_failed = True
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Network Watcher {network_watcher.name} from subscription {subscription} has no flow logs"
                findings.append(report)

        return findings
