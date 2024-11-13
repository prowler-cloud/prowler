from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_watcher_enabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            report = Check_Report_Azure(self.metadata())
            report.subscription = subscription
            report.resource_name = "Network Watcher"
            report.location = "global"
            report.resource_id = f"/subscriptions/{network_client.subscriptions[subscription]}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_*"

            missing_locations = set(network_client.locations[subscription]) - set(
                network_watcher.location for network_watcher in network_watchers
            )

            if missing_locations:
                report.status = "FAIL"
                report.status_extended = f"Network Watcher is not enabled for the following locations in subscription '{subscription}': {', '.join(missing_locations)}."
            else:
                report.status = "PASS"
                report.status_extended = f"Network Watcher is enabled for all locations in subscription '{subscription}'."

            findings.append(report)

        return findings
