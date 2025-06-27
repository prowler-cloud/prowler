from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_smb_channel_encryption_using_recommended_algorithm(Check):
    """
    Ensure SMB channel encryption for file shares is set to the recommended algorithm (AES-256-GCM or higher).

    This check evaluates whether SMB file shares are configured to use only the recommended SMB channel encryption algorithms.
    - PASS: Storage account has the recommended SMB channel encryption (AES-256-GCM or higher) enabled for file shares.
    - FAIL: Storage account does not have the recommended SMB channel encryption enabled for file shares or uses an unsupported algorithm.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
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
