from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_directory_sync_object_takeover_blocked(Check):
    """Check that directory sync blocks object takeover via soft-match and hard-match.

    When on-premises directory synchronization is enabled, an attacker who can
    write to on-premises AD can craft an object that matches a privileged cloud
    account and take it over. Both blockSoftMatchEnabled and
    blockCloudObjectTakeoverThroughHardMatchEnabled must be true to prevent this.

    - PASS: Both block flags are enabled, or tenant is cloud-only.
    - FAIL: Either block flag is disabled, or cannot verify due to insufficient permissions.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []

        if entra_client.directory_sync_error:
            for organization in entra_client.organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                if organization.on_premises_sync_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Cannot verify object takeover protection for {organization.name}: {entra_client.directory_sync_error}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Entra organization {organization.name} is cloud-only (no on-premises sync), object takeover protection is not applicable."
                findings.append(report)
            return findings

        for sync_settings in entra_client.directory_sync_settings:
            report = CheckReportM365(
                self.metadata(),
                resource=sync_settings,
                resource_id=sync_settings.id,
                resource_name=f"Directory Sync {sync_settings.id}",
            )

            soft_match_blocked = sync_settings.block_soft_match_enabled
            hard_match_blocked = (
                sync_settings.block_cloud_object_takeover_through_hard_match_enabled
            )

            if soft_match_blocked and hard_match_blocked:
                report.status = "PASS"
                report.status_extended = f"Entra directory sync {sync_settings.id} blocks both soft-match and hard-match object takeover."
            else:
                report.status = "FAIL"
                disabled_flags = []
                if not soft_match_blocked:
                    disabled_flags.append("blockSoftMatchEnabled")
                if not hard_match_blocked:
                    disabled_flags.append(
                        "blockCloudObjectTakeoverThroughHardMatchEnabled"
                    )
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} does not block object takeover: "
                    f"{', '.join(disabled_flags)} is disabled."
                )

            findings.append(report)

        if not entra_client.directory_sync_settings:
            for organization in entra_client.organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "PASS"
                report.status_extended = f"Entra organization {organization.name} is cloud-only (no on-premises sync), object takeover protection is not applicable."
                findings.append(report)

        return findings
