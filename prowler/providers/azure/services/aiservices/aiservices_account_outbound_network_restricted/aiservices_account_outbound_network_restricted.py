from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)


class aiservices_account_outbound_network_restricted(Check):
    """AI services account restricts outbound network access."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate outbound network restriction on every AI services account.

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
                if account.restrict_outbound_network_access:
                    report.status = "PASS"
                    report.status_extended = f"{prefix} restricts outbound network access to an allowed FQDN list."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} allows unrestricted outbound network access."
                    )
                findings.append(report)
        return findings
