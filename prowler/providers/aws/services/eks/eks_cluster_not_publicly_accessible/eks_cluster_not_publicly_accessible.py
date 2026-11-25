from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_cluster_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "PASS"
            report.status_extended = (
                f"EKS cluster {cluster.name} is not publicly accessible."
            )
            if cluster.endpoint_public_access:
                unrestricted_cidrs = [
                    cidr
                    for cidr in ("0.0.0.0/0", "::/0")
                    if cidr in cluster.public_access_cidrs
                ]
                if unrestricted_cidrs:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"EKS cluster {cluster.name} is publicly accessible from "
                        f"{', '.join(unrestricted_cidrs)}."
                    )
                else:
                    report.status_extended = (
                        f"EKS cluster {cluster.name} has no unrestricted CIDR "
                        "in its public access list."
                    )
            findings.append(report)

        return findings
