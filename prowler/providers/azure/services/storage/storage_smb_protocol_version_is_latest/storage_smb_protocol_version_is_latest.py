from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.lib.constants import LATEST_SMB_VERSION
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_smb_protocol_version_is_latest(Check):
    """
    Ensure SMB protocol version for file shares is set to the latest version.

    This check evaluates whether SMB file shares are configured to use only the latest SMB protocol version.
    - PASS: Storage account allows only the latest SMB protocol version for file shares.
    - FAIL: Storage account allows other SMB protocol versions for file shares.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription, storage_accounts in storage_client.storage_accounts.items():
            for account in storage_accounts:
                if getattr(account, "file_service_properties", None) and getattr(
                    account.file_service_properties.smb_protocol_settings,
                    "supported_versions",
                    None,
                ):
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=account.file_service_properties,
                    )
                    report.subscription = subscription
                    report.resource_name = account.name
                    report.location = account.location
                    if (
                        len(
                            account.file_service_properties.smb_protocol_settings.supported_versions
                        )
                        == 1
                        and account.file_service_properties.smb_protocol_settings.supported_versions[
                            0
                        ]
                        == LATEST_SMB_VERSION
                    ):
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} allows only the latest SMB protocol version ({LATEST_SMB_VERSION}) for file shares."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} from subscription {subscription} allows SMB protocol versions: {', '.join(account.file_service_properties.smb_protocol_settings.supported_versions) if account.file_service_properties.smb_protocol_settings.supported_versions else 'None'}. Only the latest SMB protocol version ({LATEST_SMB_VERSION}) should be allowed."
                    findings.append(report)
        return findings
