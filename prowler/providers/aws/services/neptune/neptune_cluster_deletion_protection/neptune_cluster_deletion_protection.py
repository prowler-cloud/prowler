from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_cluster_deletion_protection(Check):
    def execute(self):
        findings = []
        for cluster in neptune_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.resource_id = cluster.name
            report.status = "FAIL"
            report.status_extended = f"Neptune Cluster {cluster.name} does not have deletion protection enabled."
            if cluster.deletion_protection:
                report.status = "PASS"
                report.status_extended = (
                    f"Neptune Cluster {cluster.name} has deletion protection enabled."
                )

            findings.append(report)

        return findings
