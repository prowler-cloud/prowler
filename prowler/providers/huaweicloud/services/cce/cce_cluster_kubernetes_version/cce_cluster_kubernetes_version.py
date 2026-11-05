from prowler.lib.check.models import Check, CheckReportHuaweiCloud
from prowler.providers.huaweicloud.services.cce.cce_client import cce_client

MIN_K8S_VERSION = "1.25"


class cce_cluster_kubernetes_version(Check):
    """Check if CCE clusters are running outdated Kubernetes versions."""

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

            version = cluster.version
            if not version:
                report.status = "FAIL"
                report.status_extended = f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) has no Kubernetes version information."
                findings.append(report)
                continue

            try:
                parts = version.lstrip("v").split(".")
                major_minor = f"{parts[0]}.{parts[1]}"
                if major_minor < MIN_K8S_VERSION:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) is running Kubernetes {version}, "
                        f"which is below the minimum recommended version {MIN_K8S_VERSION}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) is running Kubernetes {version}."
            except (IndexError, ValueError):
                report.status = "FAIL"
                report.status_extended = f"CCE cluster '{cluster.name}' ({cluster.cluster_id}) has an unparseable Kubernetes version '{version}'."

            findings.append(report)

        return findings
