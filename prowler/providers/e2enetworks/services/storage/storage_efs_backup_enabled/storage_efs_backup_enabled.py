from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_efs_backup_enabled(Check):
    """Check if E2E Networks EFS volumes have backup enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for volume in storage_client.efs_volumes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = f"EFS volume {volume.name} has backup enabled."
            if not volume.is_backup_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"EFS volume {volume.name} does not have backup enabled."
                )
            findings.append(report)
        return findings
