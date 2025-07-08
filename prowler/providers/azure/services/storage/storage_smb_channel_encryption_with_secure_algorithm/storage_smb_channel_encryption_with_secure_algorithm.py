from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client

SECURE_ENCRYPTION_ALGORITHMS = ["AES-256-GCM"]


class storage_smb_channel_encryption_with_secure_algorithm(Check):
    """
    Ensure SMB channel encryption for file shares is set to the recommended algorithm (AES-256-GCM or higher).

    This check evaluates whether SMB file shares are configured to use only the recommended SMB channel encryption algorithms.
    - PASS: Storage account has the recommended SMB channel encryption (AES-256-GCM or higher) enabled for file shares.
    - FAIL: Storage account does not have the recommended SMB channel encryption enabled for file shares or uses an unsupported algorithm.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for account in storage_accounts:
                if account.file_service_properties:
                    pretty_current_algorithms = (
                        ", ".join(
                            account.file_service_properties.smb_protocol_settings.channel_encryption
                        )
                        if account.file_service_properties.smb_protocol_settings.channel_encryption
                        else "none"
                    )
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=account.file_service_properties,
                    )
                    report.subscription = subscription
                    report.resource_name = account.name

                    if (
                        not account.file_service_properties.smb_protocol_settings.channel_encryption
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} does not have SMB channel encryption enabled for file shares."
                    elif any(
                        algorithm in SECURE_ENCRYPTION_ALGORITHMS
                        for algorithm in account.file_service_properties.smb_protocol_settings.channel_encryption
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} has a secure algorithm for SMB channel encryption ({', '.join(SECURE_ENCRYPTION_ALGORITHMS)}) enabled for file shares since it supports {pretty_current_algorithms}."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} does not have SMB channel encryption with a secure algorithm for file shares since it supports {pretty_current_algorithms}."

                    findings.append(report)
        return findings
