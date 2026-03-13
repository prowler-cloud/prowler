from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_watcher_enabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription, network_watchers in network_client.network_watchers.items():
            missing_locations = set(network_client.locations[subscription]) - set(
                network_watcher.location for network_watcher in network_watchers
            )

            if missing_locations:
                # Report against the subscription when network watchers are missing
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_name = subscription
                report.resource_id = (
                    f"/subscriptions/{network_client.subscriptions[subscription]}"
                )
                report.location = "global"
                report.status = "FAIL"
                report.status_extended = f"Network Watcher is not enabled for the following locations in subscription '{subscription}': {', '.join(missing_locations)}."
                findings.append(report)
            else:
                # Report each network watcher that exists
                for network_watcher in network_watchers:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=network_watcher
                    )
                    report.subscription = subscription
                    report.status = "PASS"
                    report.status_extended = f"Network Watcher {network_watcher.name} is enabled in location {network_watcher.location} in subscription '{subscription}'."
                    findings.append(report)

        return findings
