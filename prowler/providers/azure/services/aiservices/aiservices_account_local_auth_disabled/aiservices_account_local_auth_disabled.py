from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)


class aiservices_account_local_auth_disabled(Check):
    """AI services account has local (API key) authentication disabled."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate local authentication on every AI services account.

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
                if account.disable_local_auth:
                    report.status = "PASS"
                    report.status_extended = f"{prefix} has local (API key) authentication disabled and requires Microsoft Entra ID."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} allows local (API key) authentication."
                    )
                findings.append(report)
        return findings
