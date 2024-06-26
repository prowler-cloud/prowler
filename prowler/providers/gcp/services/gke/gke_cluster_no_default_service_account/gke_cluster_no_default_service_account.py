from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.gke.gke_client import gke_client


class gke_cluster_no_default_service_account(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for cluster in gke_client.clusters.values():
            report = Check_Report_GCP(self.metadata())
            report.project_id = cluster.project_id
            report.resource_id = cluster.id
            report.resource_name = cluster.name
            report.location = cluster.location
            report.status = "PASS"
            report.status_extended = f"GKE cluster {cluster.name} is not using the Compute Engine default service account."
            if not cluster.node_pools and cluster.service_account == "default":
                report.status = "FAIL"
                report.status_extended = f"GKE cluster {cluster.name} is using the Compute Engine default service account."
            for node_pool in cluster.node_pools:
                if node_pool.service_account == "default":
                    report.status = "FAIL"
                    report.status_extended = f"GKE cluster {cluster.name} is using the Compute Engine default service account."
                break
            findings.append(report)

        return findings
