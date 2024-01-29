from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_ensure_private_endpoints_used_to_access_storage_accounts(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.resource_name = storage_account.name
                report.resource_id = storage_account.id
                if storage_account.private_endpoint_connections:
                    report.status = "PASS"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has private endpoint connections."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} does not have private endpoint connections."
                findings.append(report)

        return findings
