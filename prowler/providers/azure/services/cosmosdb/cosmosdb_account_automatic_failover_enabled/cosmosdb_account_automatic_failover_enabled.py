from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_automatic_failover_enabled(Check):
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

                if resource.enable_automatic_failover:
                    report.status = "PASS"
                    report.status_extended = (
                        f"{resource.name} has automatic failover enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"{resource.name} does not have automatic failover enabled."
                    )

                findings.append(report)

        return findings
