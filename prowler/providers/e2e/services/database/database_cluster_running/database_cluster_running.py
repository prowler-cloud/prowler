from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_cluster_running(Check):
    """Check if E2E Cloud database clusters are in RUNNING status."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2e(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = f"Database cluster {cluster.name} is running."
            if cluster.status != "RUNNING":
                report.status = "FAIL"
                report.status_extended = f"Database cluster {cluster.name} is not running (status: {cluster.status})."
            findings.append(report)
        return findings
