from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_uses_a_supported_version(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status_extended = f"EKS cluster {cluster.name} is using version {cluster.version} that is supported by AWS."

            eks_latest_version = eks_client.audit_config.get(
                "eks_cluster_supported_versions", ["1.28", "1.29", "1.30"]
            )

            if cluster.version not in eks_latest_version:
                report.status = "FAIL"
                report.status_extended = f"EKS cluster {cluster.name} must have a version of {eks_latest_version}"

            findings.append(report)

        return findings
