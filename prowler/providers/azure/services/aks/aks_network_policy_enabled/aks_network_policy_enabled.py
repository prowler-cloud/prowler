from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_network_policy_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription_id, clusters in aks_client.clusters.items():
            subscription_name = aks_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for cluster_id, cluster in clusters.items():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_id
                report.status = "PASS"
                report.status_extended = f"Network policy is enabled for cluster '{cluster.name}' in subscription '{subscription_name} ({subscription_id})'."

                # ARM API >= 2024-05-01 returns "none" instead of omitting the field
                network_policy = str(
                    getattr(
                        cluster.network_policy, "value", cluster.network_policy or ""
                    )
                )
                if network_policy.strip().lower() in ("", "none"):
                    report.status = "FAIL"
                    report.status_extended = f"Network policy is not enabled for cluster '{cluster.name}' in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
