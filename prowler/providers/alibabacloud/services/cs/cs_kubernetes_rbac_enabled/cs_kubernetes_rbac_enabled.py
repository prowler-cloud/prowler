from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_rbac_enabled(Check):
    """Check if RBAC authorization is enabled on Kubernetes Engine Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.rbac_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Kubernetes cluster {cluster.name} has RBAC authorization enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Kubernetes cluster {cluster.name} does not have RBAC authorization enabled or is using legacy ABAC authorization."

            findings.append(report)

        return findings
