from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_automatic_failover_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=account
                )
                report.subscription = subscription

                if account.enable_automatic_failover:
                    report.status = "PASS"
                    report.status_extended = (
                        f"CosmosDB account {account.name} has automatic failover enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CosmosDB account {account.name} does not have automatic failover enabled."
                    )

                findings.append(report)

        return findings
