from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_control_plane_logging_all_types_enabled(Check):
    def execute(self):
        findings = []
        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.status = "FAIL"
            report.status_extended = (
                f"Control plane logging is not enabled for EKS cluster {cluster.name}"
            )
            if cluster.logging and cluster.logging.enabled:
                if all(
                    item in cluster.logging.types
                    for item in [
                        "api",
                        "audit",
                        "authenticator",
                        "controllerManager",
                        "scheduler",
                    ]
                ):
                    report.status = "PASS"
                    report.status_extended = f"Control plane logging enabled and correctly configured for EKS cluster {cluster.name}"
                else:
                    report.status_extended = f"Control plane logging enabled but not all log types collected for EKS cluster {cluster.name}"
            findings.append(report)

        return findings
