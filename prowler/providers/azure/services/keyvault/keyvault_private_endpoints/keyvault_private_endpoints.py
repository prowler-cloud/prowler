from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_private_endpoints(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                report = Check_Report_Azure(metadata=self.metadata(), resource=keyvault)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} is not using private endpoints."
                if (
                    keyvault.properties
                    and keyvault.properties.private_endpoint_connections
                ):
                    report.status = "PASS"
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} is using private endpoints."
                findings.append(report)
        return findings
