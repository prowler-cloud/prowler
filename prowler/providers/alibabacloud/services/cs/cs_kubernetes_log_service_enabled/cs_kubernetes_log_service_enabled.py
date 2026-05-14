from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_log_service_enabled(Check):
    """Check if Log Service is enabled on Kubernetes Engine Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.log_service_enabled:
                report.status = "PASS"
                report.status_extended = f"Kubernetes cluster {cluster.name} has Log Service enabled with project: {cluster.audit_project_name}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} does not have Log Service enabled."

            findings.append(report)

        return findings
