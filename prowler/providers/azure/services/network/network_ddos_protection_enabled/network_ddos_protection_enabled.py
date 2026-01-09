from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client

class network_ddos_protection_enabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription, virtual_networks in network_client.virtual_networks.items():
            for vnet in virtual_networks:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=vnet
                )
                report.subscription = subscription
                report.resource_name = vnet.name
                report.resource_id = vnet.id
                report.location = vnet.location

                # Check if DDoS protection is enabled
                if vnet.ddos_protection_plan or vnet.enable_ddos_protection:
                    report.status = "PASS"
                    report.status_extended = (
                        f"VNet {vnet.name} in subscription {subscription} has DDoS protection enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"VNet {vnet.name} in subscription {subscription} does not have DDoS protection enabled."
                    )

                findings.append(report)

        return findings 