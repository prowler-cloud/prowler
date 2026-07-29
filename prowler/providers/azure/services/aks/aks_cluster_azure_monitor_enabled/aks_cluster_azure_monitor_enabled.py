from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_azure_monitor_enabled(Check):
    """
    Ensure Azure Monitor is enabled for AKS clusters.

    This check evaluates whether each Azure Kubernetes Service cluster has Azure Monitor integration enabled for metrics collection, log aggregation, and alerting.

    - PASS: The cluster has Azure Monitor enabled.
    - FAIL: The cluster does not have Azure Monitor enabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster in clusters.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_name

                if cluster.azure_monitor_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Cluster '{cluster.name}' has Azure Monitor managed Prometheus metrics enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster '{cluster.name}' does not have Azure Monitor managed Prometheus metrics enabled."

                findings.append(report)

        return findings
