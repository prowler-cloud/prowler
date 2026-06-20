from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_cluster_backup_enabled(Check):
    """Check if E2E Cloud database clusters have backups enabled."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2e(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = f"Database cluster {cluster.name} has backups enabled."
            if not cluster.backup_enabled:
                report.status = "FAIL"
                report.status_extended = f"Database cluster {cluster.name} does not have backups enabled."
            findings.append(report)
        return findings
