from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_backup_policy_continuous(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=account
                )
                report.subscription = subscription

                if account.backup_policy_type == "Continuous":
                    report.status = "PASS"
                    report.status_extended = (
                        f"CosmosDB account {account.name} uses continuous backup policy."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CosmosDB account {account.name} does not use continuous backup policy."
                    )

                findings.append(report)

        return findings
