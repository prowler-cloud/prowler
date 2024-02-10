from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.cosmosdb.cosmosdb_client import cosmosdb_client


class cosmosdb_firewall_use_selected_networks(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, accounts in cosmosdb_client.accounts.items():
            for account in accounts:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = account.name
                report.resource_id = account.id
                report.status = "FAIL"
                report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} has firewall rules that allow access from all networks."
                if account.is_virtual_network_filter_enabled:
                    report.status = "PASS"
                    report.status_extended = f"CosmosDB account {account.name} from subscription {subscription} has firewall rules that allow access only from selected networks."
                findings.append(report)

        return findings
