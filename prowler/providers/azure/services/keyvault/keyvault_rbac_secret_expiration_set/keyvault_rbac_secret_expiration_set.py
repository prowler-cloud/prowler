from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_rbac_secret_expiration_set(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if keyvault.properties.enable_rbac_authorization and keyvault.secrets:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = keyvault.name
                    report.resource_id = keyvault.id
                    report.status = "PASS"
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has all the secrets with expiration date set."
                    has_secret_without_expiration = False
                    for secret in keyvault.secrets:
                        if not secret.attributes.expires and secret.attributes.enabled:
                            report.status = "FAIL"
                            report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has the secret {secret.name} without expiration date set."
                            has_secret_without_expiration = True
                            findings.append(report)
                    if not has_secret_without_expiration:
                        findings.append(report)
        return findings
