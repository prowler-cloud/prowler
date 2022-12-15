from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_kms_cmk_encryption_in_secrets_enabled(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.status = "FAIL"
            report.status_extended = (
                f"EKS cluster {cluster.name} has not encryption for Kubernetes secrets."
            )
            if cluster.encryptionConfig:
                report.status = "PASS"
                report.status_extended = (
                    f"EKS cluster {cluster.name} has encryption for Kubernetes secrets."
                )

            findings.append(report)

        return findings
