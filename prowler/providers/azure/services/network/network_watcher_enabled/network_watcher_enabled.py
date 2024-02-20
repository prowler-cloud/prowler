from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_watcher_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        nw_locations = []
        for subscription, network_watchers in network_client.network_watchers.items():
            for network_watcher in network_watchers:
                nw_locations.append(network_watcher.location)
        for subscription, locations in network_client.locations.items():
            for location in locations:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = "Network Watcher"
                report.resource_id = f"/subscriptions/{subscription}/providers/Microsoft.Network/networkWatchers/{location}"
                if location not in nw_locations:
                    report.status = "FAIL"
                    report.status_extended = f"Network Watcher is not enabled for the location {location} in subscription {subscription}."
                    findings.append(report)
                else:
                    report.status = "PASS"
                    report.status_extended = f"Network Watcher is enabled for the location {location} in subscription {subscription}."
                    findings.append(report)

        return findings
