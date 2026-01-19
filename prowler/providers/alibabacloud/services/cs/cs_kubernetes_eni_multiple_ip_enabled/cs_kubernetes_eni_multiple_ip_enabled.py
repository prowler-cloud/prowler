from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_eni_multiple_ip_enabled(Check):
    """Check if ENI multiple IP mode is supported on Kubernetes Engine Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.eni_multiple_ip_enabled:
                report.status = "PASS"
                report.status_extended = f"Kubernetes cluster {cluster.name} supports ENI multiple IP mode via Terway plugin."
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} does not support ENI multiple IP mode (requires Terway network plugin)."

            findings.append(report)

        return findings
