from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_cloudmonitor_enabled(Check):
    """Check if CloudMonitor is enabled on Kubernetes Engine Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.cloudmonitor_enabled:
                report.status = "PASS"
                report.status_extended = f"Kubernetes cluster {cluster.name} has CloudMonitor Agent enabled on all node pools."
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} does not have CloudMonitor Agent enabled on all node pools."

            findings.append(report)

        return findings
