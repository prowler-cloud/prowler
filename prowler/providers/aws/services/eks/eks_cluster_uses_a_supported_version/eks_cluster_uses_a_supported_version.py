from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_uses_a_supported_version(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        eks_cluster_oldest_version_supported = eks_client.audit_config.get(
            "eks_cluster_oldest_version_supported", "1.28"
        )
        eks_version_major, eks_version_minor = map(
            int, eks_cluster_oldest_version_supported.split(".")
        )

        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags

            cluster_version_major, cluster_version_minor = map(
                int, cluster.version.split(".")
            )

            if (cluster_version_major < eks_version_major) or (
                cluster_version_major == eks_version_major
                and cluster_version_minor < eks_version_minor
            ):
                report.status = "FAIL"
                report.status_extended = f"EKS cluster {cluster.name} is using version {cluster.version}. It should be one of the supported versions: {eks_cluster_oldest_version_supported} or higher."
            else:
                report.status = "PASS"
                report.status_extended = f"EKS cluster {cluster.name} is using version {cluster.version} that is supported by AWS."

            findings.append(report)

        return findings
