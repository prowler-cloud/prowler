from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_directory_sync_object_takeover_blocked(Check):
    """Check that directory sync blocks object takeover via soft-match and hard-match.

    When on-premises directory synchronization is enabled, an attacker who can
    write to on-premises AD can craft an object that matches a privileged cloud
    account and take it over. Both blockSoftMatchEnabled and
    blockCloudObjectTakeoverThroughHardMatchEnabled must be true to prevent this.

    The attack path only exists on hybrid tenants, so the tenant's
    organization.onPremisesSyncEnabled is evaluated first. Microsoft Graph
    returns an onPremisesSynchronization object (with all features disabled) even
    for cloud-only tenants, so the directory sync features must not be evaluated
    unless on-premises synchronization is actually enabled.

    - PASS: The tenant is cloud-only, or both block flags are enabled.
    - FAIL: On-premises sync is enabled and either block flag is disabled.
    - MANUAL: On-premises sync is enabled but the settings cannot be read
      (insufficient permissions) or were not returned by Microsoft Graph.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []

        organizations = entra_client.organizations or []
        on_premises_sync_enabled = any(
            organization.on_premises_sync_enabled for organization in organizations
        )

        # Cloud-only tenant: the object takeover attack path does not exist, so
        # the directory sync features are not evaluated even if Microsoft Graph
        # returns an (all-disabled) onPremisesSynchronization object.
        if organizations and not on_premises_sync_enabled:
            for organization in organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Entra organization {organization.name} is cloud-only "
                    "(no on-premises sync), object takeover protection is not "
                    "applicable."
                )
                findings.append(report)
            return findings

        # Hybrid tenant but the directory sync settings could not be read.
        if entra_client.directory_sync_error:
            for organization in organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Cannot verify object takeover protection for "
                    f"{organization.name}: {entra_client.directory_sync_error}."
                )
                findings.append(report)
            return findings

        for sync_settings in entra_client.directory_sync_settings:
            report = CheckReportM365(
                self.metadata(),
                resource=sync_settings,
                resource_id=sync_settings.id,
                resource_name=f"Directory Sync {sync_settings.id}",
            )

            disabled_flags = []
            if not sync_settings.block_soft_match_enabled:
                disabled_flags.append("blockSoftMatchEnabled")
            if not sync_settings.block_cloud_object_takeover_through_hard_match_enabled:
                disabled_flags.append("blockCloudObjectTakeoverThroughHardMatchEnabled")

            if not disabled_flags:
                report.status = "PASS"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} blocks both soft-match "
                    "and hard-match object takeover."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} does not block object "
                    f"takeover: {', '.join(disabled_flags)} disabled."
                )

            findings.append(report)

        # Hybrid tenant that reported on-premises sync but returned no settings.
        if not entra_client.directory_sync_settings:
            for organization in organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Entra organization {organization.name} has on-premises sync "
                    "enabled, but no directory sync settings were returned. Review "
                    "the tenant configuration manually."
                )
                findings.append(report)

        return findings
