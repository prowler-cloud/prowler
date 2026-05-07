from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_defender_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster in clusters.values():
                report = Check_Report_Azure(
                    metadata=self.metadata(), resource=cluster
                )
                report.subscription = subscription_name

                if cluster.defender_enabled:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Cluster '{cluster.name}' has Defender for Containers enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Cluster '{cluster.name}' does not have Defender for Containers enabled."
                    )

                findings.append(report)

        return findings
