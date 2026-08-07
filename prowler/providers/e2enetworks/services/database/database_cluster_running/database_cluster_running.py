from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.database.database_client import (
    database_client,
)


class database_cluster_running(Check):
    """Check if E2E Networks database clusters are in RUNNING status."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = f"Database cluster {cluster.name} is running."
            if cluster.status != "RUNNING":
                report.status = "FAIL"
                report.status_extended = f"Database cluster {cluster.name} is not running (status: {cluster.status})."
            findings.append(report)
        return findings
