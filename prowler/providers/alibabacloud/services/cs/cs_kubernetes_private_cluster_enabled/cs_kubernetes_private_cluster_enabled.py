from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_private_cluster_enabled(Check):
    """Check if Kubernetes Cluster is created with Private cluster enabled."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.private_cluster_enabled:
                report.status = "PASS"
                report.status_extended = f"Kubernetes cluster {cluster.name} is a private cluster (no public API endpoint)."
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} has a public API endpoint exposed."

            findings.append(report)

        return findings
