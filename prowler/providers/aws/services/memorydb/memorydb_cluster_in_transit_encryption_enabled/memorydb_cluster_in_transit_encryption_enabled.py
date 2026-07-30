from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.memorydb.memorydb_client import memorydb_client


class memorydb_cluster_in_transit_encryption_enabled(Check):
    def execute(self):
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
