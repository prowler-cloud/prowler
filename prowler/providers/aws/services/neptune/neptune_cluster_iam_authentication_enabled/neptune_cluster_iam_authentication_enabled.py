from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.neptune.neptune_client import neptune_client


class neptune_cluster_iam_authentication_enabled(Check):
    def execute(self):
        findings = []
        for cluster in neptune_client.clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = f"Neptune Cluster {cluster.name} does not have IAM authentication enabled."
            if cluster.iam_auth:
                report.status = "PASS"
                report.status_extended = (
                    f"Neptune Cluster {cluster.name} has IAM authentication enabled."
                )

            findings.append(report)

        return findings
