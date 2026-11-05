from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)
from prowler.providers.azure.services.aiservices.aiservices_service import Account

KEY_VAULT_KEY_SOURCE = "Microsoft.KeyVault"


def uses_customer_managed_key(account: Account) -> bool:
    """Decide whether the account is encrypted with a customer-managed key.

    Args:
        account: AI services account.

    Returns:
        True when the account counts as encrypted with a customer-managed key.
        A Key Vault key source passes even when no key name is reported.
    """
    return (account.encryption_key_source or "").lower() == KEY_VAULT_KEY_SOURCE.lower()


class aiservices_account_encrypted_with_cmk(Check):
    """AI services account is encrypted with a customer-managed key."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate encryption key source on every AI services account.

        Returns:
            One finding per account.
        """
        findings = []
        for subscription_id, accounts in aiservices_client.accounts.items():
            subscription_name = aiservices_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for account in accounts.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription_id
                prefix = f"AI services account {account.name} (kind {account.kind}) from subscription {subscription_name} ({subscription_id})"
                if uses_customer_managed_key(account):
                    report.status = "PASS"
                    if account.encryption_key_name:
                        report.status_extended = f"{prefix} is encrypted with customer-managed key {account.encryption_key_name}."
                    else:
                        report.status_extended = f"{prefix} is encrypted with a customer-managed key from Azure Key Vault."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} is encrypted with a Microsoft-managed key."
                    )
                findings.append(report)
        return findings
