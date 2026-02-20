from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_seamless_sso_disabled(Check):
    """Check that Seamless Single Sign-On (SSO) is disabled for Microsoft Entra hybrid deployments.

    Seamless SSO allows users to sign in without typing their passwords when on
    corporate devices connected to the corporate network. When an Entra Connect server
    is compromised, Seamless SSO can enable lateral movement between on-premises domains
    and Entra ID, and it can also be exploited for brute force attacks. Modern devices with
    Primary Refresh Token (PRT) support make this feature unnecessary for most organizations.

    - PASS: Seamless SSO is disabled or on-premises sync is not enabled (cloud-only).
    - FAIL: Seamless SSO is enabled in a hybrid deployment, or cannot verify due to insufficient permissions.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the Seamless SSO disabled check.

        Checks the directory sync settings to determine if Seamless SSO is enabled.
        For hybrid environments, this check verifies the actual Seamless SSO configuration
        rather than inferring from on-premises sync status.

        Returns:
            A list of CheckReportM365 objects with the result of the check.
        """
        findings = []

        # Check if there was an error retrieving directory sync settings
        if entra_client.directory_sync_error:
            for organization in entra_client.organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                # Only FAIL for hybrid orgs; cloud-only orgs don't need this permission
                if organization.on_premises_sync_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Cannot verify Seamless SSO status for {organization.name}: {entra_client.directory_sync_error}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Entra organization {organization.name} is cloud-only (no on-premises sync), Seamless SSO is not applicable."
                findings.append(report)
            return findings

        # Process directory sync settings if available
        for sync_settings in entra_client.directory_sync_settings:
            report = CheckReportM365(
                self.metadata(),
                resource=sync_settings,
                resource_id=sync_settings.id,
                resource_name=f"Directory Sync {sync_settings.id}",
            )

            if sync_settings.seamless_sso_enabled:
                report.status = "FAIL"
                report.status_extended = f"Entra directory sync {sync_settings.id} has Seamless SSO enabled, which can be exploited for lateral movement and brute force attacks."
            else:
                report.status = "PASS"
                report.status_extended = f"Entra directory sync {sync_settings.id} has Seamless SSO disabled."

            findings.append(report)

        # If no directory sync settings and no error, it's a cloud-only tenant
        if not entra_client.directory_sync_settings:
            for organization in entra_client.organizations:
                report = CheckReportM365(
                    self.metadata(),
                    resource=organization,
                    resource_id=organization.id,
                    resource_name=organization.name,
                )
                report.status = "PASS"
                report.status_extended = f"Entra organization {organization.name} is cloud-only (no on-premises sync), Seamless SSO is not applicable."
                findings.append(report)

        return findings
