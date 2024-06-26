from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_network_policy_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster_id, cluster in clusters.items():
                report = Check_Report_Azure(self.metadata())
                report.status = "PASS"
                report.subscription = subscription_name
                report.resource_name = cluster.name
                report.resource_id = cluster_id
                report.location = cluster.location
                report.status_extended = f"Network policy is enabled for cluster '{cluster.name}' in subscription '{subscription_name}'."

                if not getattr(cluster, "network_policy", False):
                    report.status = "FAIL"
                    report.status_extended = f"Network policy is not enabled for cluster '{cluster.name}' in subscription '{subscription_name}'."

                findings.append(report)

        return findings
