from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_private_nodes_enabled(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "PASS"
            report.status_extended = (
                f"EKS cluster {cluster.name} is created with private nodes."
            )
            if not cluster.endpoint_private_access:
                report.status = "FAIL"
                report.status_extended = f"Cluster endpoint private access is not enabled for EKS cluster {cluster.name}."
            findings.append(report)

        return findings
