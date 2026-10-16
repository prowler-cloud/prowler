from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cce.cce_client import cce_client


class cce_cluster_public_endpoint(Check):
    """Check if CCE clusters have public API endpoints exposed."""

    def execute(self) -> list[CheckReportHuaweiCloud]:
        findings = []
        for cluster in cce_client.clusters:
            report = CheckReportHuaweiCloud(
                metadata=self.metadata(),
                resource=cluster,
            )
            report.region = cluster.region
            report.resource_id = cluster.cluster_id
            report.resource_arn = f"huaweicloud:cce:{cluster.region}:{cce_client.audited_account}:cluster/{cluster.cluster_id}"

            if cluster.has_public_endpoint:
                report.status = "FAIL"
                report.status_extended = f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) has a public API endpoint exposed to the internet."
            else:
                report.status = "PASS"
                report.status_extended = f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) does not have a public API endpoint."

            findings.append(report)

        return findings
