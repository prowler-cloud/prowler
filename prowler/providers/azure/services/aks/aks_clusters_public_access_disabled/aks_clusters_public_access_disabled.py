from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_clusters_public_access_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster_id, cluster in clusters.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "FAIL"
                report.subscription = subscription_name
                report.resource_name = cluster.name
                report.resource_id = cluster_id
                report.location = cluster.location
                report.status_extended = f"Public access to nodes is enabled for cluster '{cluster.name}' in subscription '{subscription_name}'"

                if cluster.private_fqdn:
                    for agent_pool in cluster.agent_pool_profiles:
                        if not getattr(agent_pool, "enable_node_public_ip", False):
                            report.status = "PASS"
                            report.status_extended = f"Public access to nodes is disabled for cluster '{cluster.name}' in subscription '{subscription_name}'"

                findings.append(report)

        return findings
