from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_secret_expiration_set_for_non_rbac_keyvault(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if (
                    not keyvault.properties.enable_rbac_authorization
                    and keyvault.secrets
                ):
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = keyvault.name
                    report.resource_id = keyvault.id
                    report.status = "PASS"
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has all the secrets with expiration date set."
                    for secret in keyvault.secrets:
                        if not secret.attributes.expires and secret.attributes.enabled:
                            report.status = "FAIL"
                            report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has a secret without expiration date set."
                            break

                    findings.append(report)
        return findings
