from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_not_publicly_accessible(Check):
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
                f"EKS cluster {cluster.name} is not publicly accessible."
            )
            if (
                cluster.endpoint_public_access
                and "0.0.0.0/0" in cluster.public_access_cidrs
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} is publicly accessible."
                )
            findings.append(report)

        return findings
