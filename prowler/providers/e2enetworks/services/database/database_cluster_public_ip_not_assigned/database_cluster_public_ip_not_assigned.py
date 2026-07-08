from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.database.database_client import (
    database_client,
)


class database_cluster_public_ip_not_assigned(Check):
    """Check if E2E Networks database clusters do not expose a public IP on the master node."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for cluster in database_client.clusters:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = f"Database cluster {cluster.name} master node does not have a public IP."
            if cluster.master_has_public_ip:
                report.status = "FAIL"
                report.status_extended = f"Database cluster {cluster.name} master node has a public IP assigned."
            findings.append(report)
        return findings
