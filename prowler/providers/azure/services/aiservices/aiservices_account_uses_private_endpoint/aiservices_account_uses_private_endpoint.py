from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)

APPROVED_STATUS = "approved"


class aiservices_account_uses_private_endpoint(Check):
    """AI services account has an approved private endpoint connection."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate private endpoint connections on every AI services account.

        Pending and rejected connections carry no traffic, so only an
        approved connection passes.

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
                if any(
                    status.lower() == APPROVED_STATUS
                    for status in account.private_endpoint_connection_statuses
                ):
                    report.status = "PASS"
                    report.status_extended = (
                        f"{prefix} has an approved private endpoint connection."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} has no approved private endpoint connection."
                    )
                findings.append(report)
        return findings
