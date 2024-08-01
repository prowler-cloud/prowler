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

            version_nums = cluster.version.split(".")
            if int(version_nums[0]) < 1 :
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} must have a version of 1.28 or greater."
                )

            if int(version_nums[0]) == 1 and int(version_nums[1]) < 28:
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} must have a version of 1.28 or greater."
                )


            findings.append(report)

        return findings