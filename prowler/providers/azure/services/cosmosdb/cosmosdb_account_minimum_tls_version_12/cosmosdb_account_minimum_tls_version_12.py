from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_minimum_tls_version_12(Check):
    """Ensure that Cosmos DB accounts enforce TLS 1.2 or higher."""

    def execute(self) -> Check_Report_Azure:
        """Execute the Cosmos DB minimum TLS version check.

        Iterates over every Cosmos DB account fetched by the service and reports
        PASS when `minimalTlsVersion` is `Tls12` or higher, FAIL otherwise
        (including when the property is missing or set to a legacy value).

        Returns:
            A list of Check_Report_Azure with one report per Cosmos DB account.
        """
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(metadata=self.metadata(), resource=account)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} does not enforce TLS 1.2 or higher."
                if account.minimal_tls_version in {"Tls12", "Tls13"}:
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} enforces TLS 1.2 or higher."
                findings.append(report)

        return findings
