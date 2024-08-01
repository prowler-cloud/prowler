from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client

class eks_cluster_ensure_version_is_supported(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.status = "PASS"
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status_extended = f"EKS cluster {cluster.name} version is supported."

            user_version_num = cluster.version.split(".")

            eks_latest_version = eks_client.audit_config.get(
                "eks_cluster_is_supported_version", "1.28"
            )
            eks_version_num = eks_latest_version.split(".")

            if int(user_version_num[0]) < int(eks_version_num[0]) :
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} must have a version of {eks_latest_version} or greater."
                )

            if int(user_version_num[0]) == int(eks_version_num[0]) and int(user_version_num[1]) < int(eks_version_num[1]):
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} must have a version of {eks_latest_version} or greater."
                )


            findings.append(report)

        return findings