from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_rbac_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = keyvault.name
                report.resource_id = keyvault.id
                report.location = keyvault.location
                report.status = "FAIL"
                report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} is not using RBAC for access control."
                if (
                    keyvault.properties
                    and keyvault.properties.enable_rbac_authorization
                ):
                    report.status = "PASS"
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} is using RBAC for access control."
                findings.append(report)
        return findings
