from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_cluster_backup_enabled(Check):
    def execute(self):
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
