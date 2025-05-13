from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_cluster_copy_tags_to_snapshots(Check):
    def execute(self):
        findings = []
        for cluster in neptune_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = f"Neptune DB Cluster {cluster.id} is not configured to copy tags to snapshots."
            if cluster.copy_tags_to_snapshot:
                report.status = "PASS"
                report.status_extended = f"Neptune DB Cluster {cluster.id} is configured to copy tags to snapshots."

            findings.append(report)

        return findings
