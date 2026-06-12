from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_automatic_failover_enabled(Check):
    """Ensure that Cosmos DB accounts have automatic failover enabled."""

    def execute(self) -> Check_Report_Azure:
        """Execute the Cosmos DB automatic failover check.

        Iterates over every Cosmos DB account fetched by the service and reports
        PASS when `enableAutomaticFailover` is True, FAIL otherwise.

        Returns:
            A list of Check_Report_Azure with one report per Cosmos DB account.
        """
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} does not have automatic failover enabled."
                if account.enable_automatic_failover:
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} has automatic failover enabled."
                findings.append(report)

        return findings
