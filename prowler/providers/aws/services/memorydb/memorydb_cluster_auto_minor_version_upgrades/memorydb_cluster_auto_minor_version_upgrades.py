from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.memorydb.memorydb_client import memorydb_client


class memorydb_cluster_auto_minor_version_upgrades(Check):
    def execute(self):
        findings = []
        for cluster in memorydb_client.clusters.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=cluster
            )
            if cluster.auto_minor_version_upgrade:
                report.status = "PASS"
                report.status_extended = f"Memory DB Cluster {cluster.name} has minor version upgrade enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Memory DB Cluster {cluster.name} does not have minor version upgrade enabled."

            findings.append(report)

        return findings
