from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_expiration_set_for_rbac_keyvault(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, keyvaults in keyvault_client.keyvaults.items():
            for keyvault in keyvaults:
                if keyvault.properties.enable_rbac_authorization:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = keyvault.name
                    report.resource_id = keyvault.id
                    report.status = "PASS"
                    report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has all the keys with expiration date set."
                    for key in keyvault.keys:
                        print(key.attributes)
                        if not key.attributes.expires and not key.attributes.enabled:
                            report.status = "FAIL"
                            report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has a key without expiration date set."
                            break

                findings.append(report)
        return findings
