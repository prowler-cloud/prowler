from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_rbac_secret_expiration_set(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if keyvault.properties.enable_rbac_authorization:
                    for secret in keyvault.secrets or []:
                        if not secret.enabled:
                            continue
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=secret
                        )
                        report.subscription = subscription
                        if not secret.attributes.expires:
                            report.status = "FAIL"
                            report.status_extended = f"Secret {secret.name} in Key Vault {keyvault.name} from subscription {subscription} does not have an expiration date set."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Secret {secret.name} in Key Vault {keyvault.name} from subscription {subscription} has an expiration date set."
                        findings.append(report)
        return findings
