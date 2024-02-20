from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_expiration_set_for_rbac_keyvault(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, storage_accounts in keyvault_client.keyvaults.items():
            print(subscription)
            print(storage_accounts)

        return findings
