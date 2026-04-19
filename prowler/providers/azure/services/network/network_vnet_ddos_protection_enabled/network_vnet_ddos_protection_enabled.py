from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_vnet_ddos_protection_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, vnets in network_client.virtual_networks.items():
            for vnet in vnets:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=vnet
                )
                report.subscription = subscription_name
                report.resource_name = vnet.name
                report.resource_id = vnet.id
                report.location = vnet.location

                if vnet.enable_ddos_protection:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Virtual network '{vnet.name}' has DDoS "
                        f"protection enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Virtual network '{vnet.name}' does not have "
                        f"DDoS protection enabled."
                    )

                findings.append(report)

        return findings
