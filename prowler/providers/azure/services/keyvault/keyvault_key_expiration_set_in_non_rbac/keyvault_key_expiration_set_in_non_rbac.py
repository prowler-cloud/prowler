from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_expiration_set_in_non_rbac(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            subscription_name = keyvault_client.subscriptions.get(
                subscription, subscription
            )
            for keyvault in key_vaults:
                if not keyvault.properties.enable_rbac_authorization:
                    for key in keyvault.keys or []:
                        if not key.enabled:
                            continue
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=key
                        )
                        report.subscription = subscription
                        if not key.attributes.expires:
                            report.status = "FAIL"
                            report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) does not have an expiration date set."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) has an expiration date set."
                        findings.append(report)
        return findings
