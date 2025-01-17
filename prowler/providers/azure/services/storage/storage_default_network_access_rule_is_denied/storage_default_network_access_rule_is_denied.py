from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_default_network_access_rule_is_denied(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=storage_account
                )
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has network access rule set to Deny."

                if storage_account.network_rule_set.default_action == "Allow":
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has network access rule set to Allow."

                findings.append(report)

        return findings
