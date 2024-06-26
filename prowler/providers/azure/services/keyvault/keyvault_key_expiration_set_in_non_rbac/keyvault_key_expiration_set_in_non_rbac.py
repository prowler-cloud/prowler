from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_expiration_set_in_non_rbac(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if not keyvault.properties.enable_rbac_authorization and keyvault.keys:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = keyvault.name
                    report.resource_id = keyvault.id
                    report.status = "PASS"
                    report.location = keyvault.location
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has all the keys with expiration date set."
                    has_key_without_expiration = False
                    for key in keyvault.keys:
                        if (
                            key.attributes
                            and not key.attributes.expires
                            and key.enabled
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has the key {key.name} without expiration date set."
                            has_key_without_expiration = True
                            findings.append(report)
                    if not has_key_without_expiration:
                        findings.append(report)
        return findings
