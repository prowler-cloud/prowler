from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_network_policy_enabled(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = f"EKS cluster {cluster.name} does not have a Network Policy. Cluster security group ID is not set."
            if cluster.security_group_id:
                report.status = "PASS"
                report.status_extended = f"EKS cluster {cluster.name} has a Network Policy with the security group {cluster.security_group_id}."

            findings.append(report)

        return findings
