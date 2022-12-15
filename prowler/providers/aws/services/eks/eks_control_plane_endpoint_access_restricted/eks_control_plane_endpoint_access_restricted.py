from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_control_plane_endpoint_access_restricted(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.status = "PASS"
            report.status_extended = (
                f"Cluster endpoint access is private for EKS cluster {cluster.name}"
            )
            if cluster.endpoint_public_access and not cluster.endpoint_private_access:
                if "0.0.0.0/0" in cluster.public_access_cidrs:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster control plane access is not restricted for EKS cluster {cluster.name}"
                else:
                    report.status_extended = f"Cluster control plane access is restricted for EKS cluster {cluster.name}"
            findings.append(report)

        return findings
