from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_network_policy_enabled(Check):
    """Check if Network policy is enabled on Kubernetes Engine Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.network_policy_enabled:
                report.status = "PASS"
                report.status_extended = f"Kubernetes cluster {cluster.name} has Network Policy enabled via Terway plugin."
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} does not have Network Policy enabled (requires Terway network plugin)."

            findings.append(report)

        return findings
