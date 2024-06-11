from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_watcher_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            report = Check_Report_Azure(self.metadata())
            report.subscription = subscription
            report.resource_name = "Network Watcher"
            report.location = "Global"
            report.resource_id = f"/subscriptions/{network_client.subscriptions[subscription]}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"
            report.status = "FAIL"
            report.status_extended = f"Network Watcher is not enabled for all locations in subscription '{subscription}'."

            if len(network_watchers) >= len(
                network_client.locations[subscription]
            ) and all(
                location
                in [network_watcher.location for network_watcher in network_watchers]
                for location in network_client.locations[subscription]
            ):
                report.status = "PASS"
                report.status_extended = f"Network Watcher is enabled for all locations in subscription '{subscription}'."

            findings.append(report)

        return findings
