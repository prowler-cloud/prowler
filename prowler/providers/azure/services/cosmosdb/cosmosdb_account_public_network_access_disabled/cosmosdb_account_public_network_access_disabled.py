from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_public_network_access_disabled(Check):
    """Ensure that Cosmos DB accounts have public network access disabled."""

    def execute(self) -> Check_Report_Azure:
        """Execute the Cosmos DB public network access check.

        Iterates over every Cosmos DB account fetched by the service and reports
        PASS when `publicNetworkAccess` is `Disabled` or `SecuredByPerimeter`
        (Microsoft Network Security Perimeter), FAIL otherwise (including when
        the property is missing or set to `Enabled`).

        Returns:
            A list of Check_Report_Azure with one report per Cosmos DB account.
        """
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} does not have public network access disabled (current value: {account.public_network_access!r})."
                if account.public_network_access in {"Disabled", "SecuredByPerimeter"}:
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} has public network access disabled."
                findings.append(report)

        return findings
