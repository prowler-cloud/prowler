from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_smb_channel_encryption_using_recommended_algorithm(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        # Use audit_config for configurable algorithms
        recommended_encryption_algorithms = storage_client.audit_config.get(
            "recommended_smb_channel_encryption_algorithms", ["AES-256-GCM"]
        )
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for account in storage_accounts:
                if account.file_service_properties:
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=account.file_service_properties,
                    )
                    report.subscription = subscription
                    report.resource_name = account.name
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {account.name} from subscription {subscription} does not have the recommended SMB channel encryption enabled for file shares."

                    if any(
                        algorithm in recommended_encryption_algorithms
                        for algorithm in account.file_service_properties.smb_protocol_settings.channel_encryption
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} has the recommended SMB channel encryption (AES-256-GCM) enabled for file shares."

                    findings.append(report)
        return findings
