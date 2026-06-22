from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client

DEFAULT_SECURE_ENCRYPTION_ALGORITHMS = ["AES-256-GCM"]


class storage_smb_channel_encryption_with_secure_algorithm(Check):
    """
    Ensure SMB channel encryption for file shares only allows secure algorithms (AES-256-GCM or higher by default).

    The list of allowed algorithms is configurable via
    azure.recommended_smb_channel_encryption_algorithms in the Prowler configuration file.

    This check evaluates whether SMB file shares are configured to use only the recommended SMB channel encryption algorithms.
    - PASS: Storage account only allows secure SMB channel encryption algorithms for file shares.
    - FAIL: Storage account does not have SMB channel encryption enabled, or it allows at least one algorithm that is not in the recommended list.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []
        secure_encryption_algorithms = storage_client.audit_config.get(
            "recommended_smb_channel_encryption_algorithms",
            DEFAULT_SECURE_ENCRYPTION_ALGORITHMS,
        )
        for subscription, storage_accounts in storage_client.storage_accounts.items():
            subscription_name = storage_client.subscriptions.get(
                subscription, subscription
            )
            for account in storage_accounts:
                if account.file_service_properties:
                    channel_encryption = (
                        account.file_service_properties.smb_protocol_settings.channel_encryption
                    )
                    pretty_current_algorithms = (
                        ", ".join(channel_encryption) if channel_encryption else "none"
                    )
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=account.file_service_properties,
                    )
                    report.subscription = subscription
                    report.resource_name = account.name

                    if not channel_encryption:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription_name} ({subscription}) does not have SMB channel encryption enabled for file shares."
                    elif all(
                        algorithm in secure_encryption_algorithms
                        for algorithm in channel_encryption
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription_name} ({subscription}) only allows secure algorithms for SMB channel encryption on file shares since it supports {pretty_current_algorithms}."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription_name} ({subscription}) allows insecure algorithms for SMB channel encryption on file shares since it supports {pretty_current_algorithms} and only {', '.join(secure_encryption_algorithms)} is recommended."

                    findings.append(report)
        return findings
