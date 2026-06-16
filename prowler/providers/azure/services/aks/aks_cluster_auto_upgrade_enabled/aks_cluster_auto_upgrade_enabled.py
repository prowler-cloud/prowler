from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_auto_upgrade_enabled(Check):
    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        for subscription_name, clusters in aks_client.clusters.items():
            for cluster in clusters.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_name

                auto_upgrade_channel = (
                    (cluster.auto_upgrade_channel or "").strip().lower()
                )
                if auto_upgrade_channel and auto_upgrade_channel != "none":
                    report.status = "PASS"
                    report.status_extended = (
                        f"Cluster '{cluster.name}' has auto-upgrade channel."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster '{cluster.name}' does not have auto-upgrade configured."

                findings.append(report)

        return findings
