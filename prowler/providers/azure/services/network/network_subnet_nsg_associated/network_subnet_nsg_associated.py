from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client

# Subnets that are managed by Azure and should not have custom NSGs
EXCLUDED_SUBNET_NAMES = {
    "GatewaySubnet",
    "AzureFirewallSubnet",
    "AzureFirewallManagementSubnet",
    "AzureBastionSubnet",
    "RouteServerSubnet",
}


class network_subnet_nsg_associated(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, vnets in network_client.virtual_networks.items():
            for vnet in vnets:
                for subnet in vnet.subnets:
                    if subnet.name in EXCLUDED_SUBNET_NAMES:
                        continue

                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=vnet
                    )
                    report.subscription = subscription_name
                    report.resource_name = f"{vnet.name}/{subnet.name}"
                    report.resource_id = subnet.id
                    report.location = vnet.location

                    if subnet.nsg_id:
                        report.status = "PASS"
                        report.status_extended = (
                            f"Subnet '{subnet.name}' in VNet '{vnet.name}' "
                            f"has an NSG associated."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Subnet '{subnet.name}' in VNet '{vnet.name}' "
                            f"does not have an NSG associated."
                        )

                    findings.append(report)

        return findings
