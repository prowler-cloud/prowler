from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_deletion_protection_enabled(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"EKS cluster {cluster.name} has deletion protection enabled."
            )
            if cluster.deletion_protection is False:
                report.status = "FAIL"
                report.status_extended = (
                    f"EKS cluster {cluster.name} has deletion protection disabled."
                )
            findings.append(report)

        return findings
