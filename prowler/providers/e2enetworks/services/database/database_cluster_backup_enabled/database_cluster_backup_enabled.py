from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.database.database_client import (
    database_client,
)


class database_cluster_backup_enabled(Check):
    """Check if E2E Networks database clusters have backups enabled."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"Database cluster {cluster.name} has backups enabled."
            )
            if not cluster.backup_enabled:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database cluster {cluster.name} does not have backups enabled."
                )
            findings.append(report)
        return findings
