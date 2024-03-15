from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_clusters_created_with_private_nodes(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster_id, cluster in clusters.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = cluster.name
                report.resource_id = cluster_id
                report.status_extended = f"Cluster '{cluster.name}' was created with private nodes in subscription '{subscription_name}'"

                for agent_pool in cluster.agent_pool_profiles:
                    if getattr(agent_pool, "enable_node_public_ip", True):
                        report.status = "FAIL"
                        report.status_extended = f"Cluster '{cluster.name}' was not created with private nodes in subscription '{subscription_name}'"
                        break

                findings.append(report)

        return findings
