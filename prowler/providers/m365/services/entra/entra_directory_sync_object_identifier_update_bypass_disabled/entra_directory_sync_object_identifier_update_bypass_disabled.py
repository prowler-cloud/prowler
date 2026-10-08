"""Check that the temporary onPremisesObjectIdentifier update bypass is disabled."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_directory_sync_object_identifier_update_bypass_disabled(Check):
    """Check that the temporary onPremisesObjectIdentifier update bypass is disabled.

    Since July 2026, Microsoft Entra ID enforces hard-match security protections
    that block an on-premises sync engine from taking over a cloud account that
    already has onPremisesObjectIdentifier set or holds a privileged role.
    allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled is a tenant-wide bypass
    of those protections meant only for validated migration or recovery work.
    Leaving it enabled reopens the on-prem-to-cloud account takeover path.

    The check mirrors the gating logic of
    entra_directory_sync_object_takeover_blocked:

    - PASS: The tenant is cloud-only (not applicable), or the bypass is disabled
      (false).
    - FAIL: The bypass is enabled (true) on a hybrid tenant.
    - MANUAL: The sync settings cannot be read (permissions), the property is
      absent from the response (None), no settings were returned for a hybrid
      tenant, or hybrid status is unknown (no organizations).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        organizations = entra_client.organizations or []
        on_premises_sync_enabled = any(
            organization.on_premises_sync_enabled for organization in organizations
        )

        # Cloud-only tenant: the attack path does not exist, so the directory
        # sync features are not evaluated even if Microsoft Graph returns an
        # (all-disabled) onPremisesSynchronization object.
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
                    "(no on-premises sync), onPremisesObjectIdentifier update "
                    "bypass protection is not applicable."
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
                    f"Cannot verify onPremisesObjectIdentifier update bypass "
                    f"for {organization.name}: "
                    f"{entra_client.directory_sync_error}."
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

            bypass_value = (
                sync_settings.allow_on_prem_update_of_on_premises_object_identifier_enabled
            )

            if bypass_value is None:
                # Property was not returned by Microsoft Graph; do not assume
                # false.
                report.status = "MANUAL"
                report.status_extended = (
                    f"Microsoft Graph did not return "
                    f"allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled for "
                    f"directory sync {sync_settings.id}; verify it manually "
                    f"with Get-MgDirectoryOnPremiseSynchronization."
                )
            elif bypass_value is False:
                report.status = "PASS"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} keeps hard-match "
                    f"security protections enforced: the temporary "
                    f"onPremisesObjectIdentifier update bypass is disabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} has the temporary "
                    f"bypass allowOnPremUpdateOfOnPremisesObjectIdentifierEnabled "
                    f"enabled, which weakens hard-match protections for accounts "
                    f"with onPremisesObjectIdentifier set or privileged roles. "
                    f"Disable it once migration/recovery work is complete."
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
