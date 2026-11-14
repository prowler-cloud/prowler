from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_rotation_enabled(Check):
    """Evaluate key rotation while distinguishing unavailable policy data."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the rotation policy of every listed Key Vault key.

        Returns:
            One finding per key: PASS when its rotation policy includes a
            Rotate action, FAIL when it does not, and MANUAL when the key's
            Azure Resource Manager details could not be retrieved.
        """
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            subscription_name = keyvault_client.subscriptions.get(
                subscription, subscription
            )
            for keyvault in key_vaults:
                for key in keyvault.keys or []:
                    report = Check_Report_Azure(metadata=self.metadata(), resource=key)
                    report.subscription = subscription
                    if not key.rotation_policy_accessible:
                        report.status = "MANUAL"
                        report.status_extended = f"Cannot evaluate the rotation policy of key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) because its Azure Resource Manager details could not be retrieved. Verify Microsoft.KeyVault/vaults/keys/read permission and ARM API availability."
                    elif (
                        key.rotation_policy
                        and key.rotation_policy.lifetime_actions
                        and any(
                            action.action == "Rotate"
                            for action in key.rotation_policy.lifetime_actions
                        )
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) has a rotation policy set."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) does not have a rotation policy set."
                    findings.append(report)
        return findings
