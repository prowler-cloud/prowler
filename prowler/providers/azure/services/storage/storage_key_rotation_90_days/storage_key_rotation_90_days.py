from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_key_rotation_90_days(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for storage_account in storage_accounts:
                report = Check_Report_Azure(self.metadata())
                report.subscription = subscription
                report.status = "PASS"
                report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has a valid key expiration period of {storage_account.key_expiration_period_in_days} days."
                report.resource_name = storage_account.name
                report.resource_id = storage_account.id
                if storage_account.key_expiration_period_in_days is None:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has no key expiration period set."
                else:
                    if storage_account.key_expiration_period_in_days > 90:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {storage_account.name} from subscription {subscription} has an invalid key expiration period of {storage_account.key_expiration_period_in_days} days."

                findings.append(report)

        return findings
