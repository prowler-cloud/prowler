from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_directory_sync_object_takeover_blocked(Check):
    """Check that hybrid Entra tenants block soft- and hard-match takeover."""

    def execute(self) -> List[CheckReportM365]:
        """Verify directory sync object takeover protections.

        Builds reports from the Entra client's directory sync settings. Hybrid
        tenants pass when both soft- and hard-match protections are enabled,
        fail when either protection is disabled, and require manual review when
        settings cannot be read. Cloud-only tenants pass as not applicable.

        Returns:
            List[CheckReportM365]: Reports for each sync configuration or
                organization.
        """
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
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Cannot verify directory sync object takeover protections for "
                        f"{organization.name}: {entra_client.directory_sync_error}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Entra organization {organization.name} is cloud-only "
                        "(no on-premises sync), so directory sync object takeover "
                        "protections are not applicable."
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
            disabled_protections = []
            if not sync_settings.block_soft_match_enabled:
                disabled_protections.append("soft match")
            if not sync_settings.block_cloud_object_takeover_through_hard_match_enabled:
                disabled_protections.append("hard match")

            if disabled_protections:
                report.status = "FAIL"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} does not block object "
                    f"takeover through {' and '.join(disabled_protections)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Entra directory sync {sync_settings.id} blocks object takeover "
                    "through both soft and hard matching."
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
                if organization.on_premises_sync_enabled:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Entra organization {organization.name} has on-premises sync "
                        "enabled, but no directory sync settings were returned. Review "
                        "the tenant configuration manually."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Entra organization {organization.name} is cloud-only "
                        "(no on-premises sync), so directory sync object takeover "
                        "protections are not applicable."
                    )
                findings.append(report)

        return findings
