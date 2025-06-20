from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_access_only_through_private_endpoints(Check):
    """
    Ensure that Public Network Access when using Private Endpoint is disabled.

    This check evaluates whether Azure Key Vaults with private endpoints configured have
    public network access disabled. Disabling public network access enhances security by
    isolating the Key Vault from the public internet, thereby reducing its exposure.

    - PASS: The Key Vault has private endpoints and public network access is disabled.
    - FAIL: The Key Vault has private endpoints and public network access is enabled.
    """

    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if (
                    keyvault.properties
                    and keyvault.properties.private_endpoint_connections
                ):
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=keyvault
                    )
                    report.subscription = subscription

                    if keyvault.properties.public_network_access_disabled:
                        report.status = "PASS"
                        report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has public network access disabled and is using private endpoints."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has public network access enabled while using private endpoints."
                    findings.append(report)
        return findings
