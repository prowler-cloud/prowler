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

            eks_supported_versions = eks_client.audit_config.get(
                "eks_cluster_supported_versions", "1.28"
            )

            user_version_num = cluster.version.split(".")
            eks_version_num = eks_supported_versions.split(".")

            if int(user_version_num[0]) < int(eks_version_num[0]):
                report.status = "FAIL"
                report.status_extended = f"EKS cluster {cluster.name} is in version {cluster.version}. It should be one of the next supported versions: {eks_supported_versions} or higher"

            if int(user_version_num[0]) == int(eks_version_num[0]) and int(
                user_version_num[1]
            ) < int(eks_version_num[1]):
                report.status = "FAIL"
                report.status_extended = f"EKS cluster {cluster.name} is in version {cluster.version}. It should be one of the next supported versions: {eks_supported_versions} or higher"

            findings.append(report)

        return findings
