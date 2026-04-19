from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_public_network_access_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                resource = account
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=resource
                )
                report.subscription = subscription_name
                report.resource_name = resource.name
                report.resource_id = resource.id
                report.location = resource.location

                if resource.public_network_access == "Disabled":
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has public network access disabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} has public network access enabled."
                    )

                findings.append(report)

        return findings
