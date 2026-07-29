from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_backup_policy_continuous(Check):
    """Ensure that Cosmos DB accounts use the continuous backup policy."""

    def execute(self) -> Check_Report_Azure:
        """Execute the Cosmos DB continuous-backup check.

        Iterates over every Cosmos DB account fetched by the service and reports
        PASS when `backupPolicy.type` is `Continuous`, FAIL otherwise (including
        when the property is missing).

        Returns:
            A list of Check_Report_Azure with one report per Cosmos DB account.
        """
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} does not use continuous backup policy."
                if account.backup_policy_type == "Continuous":
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} uses continuous backup policy."
                findings.append(report)

        return findings
