from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)


class aiservices_account_network_acls_default_action_deny(Check):
    """AI services account denies public network access by default."""

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the network ACL default action on every AI services account.

        PASS when public network access is disabled, or when the network ACL
        default action is `Deny` so only selected networks reach the endpoint.

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
                if not account.public_network_access:
                    report.status = "PASS"
                    report.status_extended = (
                        f"{prefix} has public network access disabled."
                    )
                elif account.network_acls_default_action == "Deny":
                    report.status = "PASS"
                    report.status_extended = f"{prefix} restricts public network access to selected networks."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{prefix} allows public network access from all networks."
                    )
                findings.append(report)
        return findings
