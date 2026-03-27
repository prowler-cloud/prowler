from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_rotation_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                for key in keyvault.keys or []:
                    report = Check_Report_Azure(metadata=self.metadata(), resource=key)
                    report.subscription = subscription
                    if (
                        key.rotation_policy
                        and key.rotation_policy.lifetime_actions
                        and any(
                            action.action == "Rotate"
                            for action in key.rotation_policy.lifetime_actions
                        )
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has the key {key.name} with rotation policy set."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Keyvault {keyvault.name} from subscription {subscription} has the key {key.name} without rotation policy set."
                    findings.append(report)
        return findings
