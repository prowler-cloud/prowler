from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_minimum_tls_version_12(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=account
                )
                report.subscription = subscription

                if account.minimal_tls_version == "Tls12":
                    report.status = "PASS"
                    report.status_extended = (
                        f"CosmosDB account {account.name} enforces TLS 1.2 or higher."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CosmosDB account {account.name} does not enforce TLS 1.2."
                    )

                findings.append(report)

        return findings
