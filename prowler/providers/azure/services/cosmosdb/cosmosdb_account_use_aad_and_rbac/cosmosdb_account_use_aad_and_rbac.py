from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_account_use_aad_and_rbac(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = account.name
                report.resource_id = account.id
                report.status = "FAIL"
                report.location = account.location
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} is not using AAD and RBAC"
                if account.disable_local_auth:
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} is using AAD and RBAC"
                findings.append(report)

        return findings
