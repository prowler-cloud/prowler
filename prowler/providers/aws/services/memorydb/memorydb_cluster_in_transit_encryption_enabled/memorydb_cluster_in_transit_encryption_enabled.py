from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.memorydb.memorydb_client import memorydb_client


class memorydb_cluster_in_transit_encryption_enabled(Check):
    """Verify that every MemoryDB cluster encrypts data in transit.

    A cluster PASSES when ``TLSEnabled`` is set. The flag can only be chosen at
    creation time, so a failing cluster has to be rebuilt from a snapshot.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the MemoryDB in-transit encryption check.

        Returns:
            A list of reports with each cluster in-transit encryption status.
        """
        findings = []
        for cluster in memorydb_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            if cluster.tls_enabled:
                report.status = "PASS"
                report.status_extended = f"Memory DB Cluster {cluster.name} has in-transit encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Memory DB Cluster {cluster.name} does not have in-transit encryption enabled."

            findings.append(report)

        return findings
