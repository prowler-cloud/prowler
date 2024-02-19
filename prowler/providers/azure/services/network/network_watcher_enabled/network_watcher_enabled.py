from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_watcher_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        nw_locations = []
        for subscription, network_watchers in network_client.network_watchers.items():
            for network_watcher in network_watchers:
                nw_locations.append(network_watcher.location)
        for subscription, security_groups in network_client.security_groups.items():
            for security_group in security_groups:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = security_group.name
                report.resource_id = security_group.id
                report.status = "PASS"
                report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has Network Watcher enabled."
                disabled_locations = set(security_group.subscription_locations) - set(
                    nw_locations
                )
                if disabled_locations:
                    report.status = "FAIL"
                    report.status_extended = f"Security Group {security_group.name} from subscription {subscription} has Network Watcher disabled for the following locations: {disabled_locations}."
                findings.append(report)

        return findings
