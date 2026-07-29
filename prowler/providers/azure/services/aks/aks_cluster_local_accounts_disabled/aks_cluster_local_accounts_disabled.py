from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_local_accounts_disabled(Check):
    """
    Ensure local accounts are disabled on AKS clusters.

    This check evaluates whether each Azure Kubernetes Service cluster has local accounts disabled, forcing all authentication through Microsoft Entra ID.

    - PASS: The cluster has local accounts disabled.
    - FAIL: The cluster has local accounts enabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster in clusters.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_name

                if cluster.local_accounts_disabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Cluster '{cluster.name}' has local accounts disabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Cluster '{cluster.name}' has local accounts enabled."
                    )

                findings.append(report)

        return findings
