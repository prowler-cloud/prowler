from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_key_rotation_enabled(Check):
    """Evaluate key rotation while distinguishing unavailable policy data."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate readable keys and report incomplete subscription coverage.

        Returns:
            Key rotation findings and one MANUAL finding per subscription
            containing keys whose ARM detail requests failed.
        """
        findings = []
        for subscription, key_vaults in keyvault_client.key_vaults.items():
            rotation_policy_unavailable = False
            subscription_name = keyvault_client.subscriptions.get(
                subscription, subscription
            )
            for keyvault in key_vaults:
                for key in keyvault.keys or []:
                    if not key.rotation_policy_accessible:
                        rotation_policy_unavailable = True
                        continue
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
                        report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) has a rotation policy set."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Key {key.name} in Key Vault {keyvault.name} from subscription {subscription_name} ({subscription}) does not have a rotation policy set."
                    findings.append(report)
            if rotation_policy_unavailable:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.subscription = subscription
                report.resource_id = f"/subscriptions/{subscription}"
                report.resource_name = subscription_name
                report.status = "MANUAL"
                report.status_extended = f"Cannot evaluate rotation policies for some keys in subscription {subscription_name} ({subscription}) because their Azure Resource Manager details could not be retrieved. Verify Microsoft.KeyVault/vaults/keys/read permission and ARM API availability."
                findings.append(report)
        return findings
