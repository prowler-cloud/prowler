from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)

NO_IDENTITY_TYPE = "none"


class aiservices_account_managed_identity_enabled(Check):
    """AI services account has a managed identity."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the managed identity of every AI services account.

        Azure reports a removed identity either as no identity block or as
        type `None`; both fail.

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
                identity_type = account.identity_type
                if identity_type and identity_type.lower() != NO_IDENTITY_TYPE:
                    report.status = "PASS"
                    report.status_extended = (
                        f"{prefix} has a managed identity ({identity_type})."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = f"{prefix} has no managed identity."
                findings.append(report)
        return findings
