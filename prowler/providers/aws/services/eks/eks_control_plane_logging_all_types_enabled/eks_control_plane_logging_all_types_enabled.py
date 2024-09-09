from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.eks.eks_client import eks_client


class eks_control_plane_logging_all_types_enabled(Check):
    def execute(self):
        findings = []
        required_log_types = eks_client.audit_config.get("eks_required_log_types", [])
        required_log_types_str = ", ".join(required_log_types)

        for cluster in eks_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = f"Control plane logging is not enabled for EKS cluster {cluster.name}. Required log types: {required_log_types_str}."
            if cluster.logging and cluster.logging.enabled:
                if all(item in cluster.logging.types for item in required_log_types):
                    report.status = "PASS"
                    report.status_extended = f"Control plane logging and all required log types are enabled for EKS cluster {cluster.name}."
                else:
                    report.status_extended = f"Control plane logging is enabled but not all required log types are enabled for EKS cluster {cluster.name}. Required log types: {required_log_types_str}. Enabled log types: {', '.join(cluster.logging.types)}."
            findings.append(report)

        return findings
