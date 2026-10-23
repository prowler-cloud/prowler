from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client

MANAGED_NODE_OS_UPGRADE_CHANNELS = {"nodeimage", "securitypatch"}


class aks_cluster_node_os_upgrade_channel_enabled(Check):
    """
    Ensure AKS clusters have a managed node OS auto-upgrade channel.

    The node OS auto-upgrade channel controls how operating system security updates reach the node VMs, separately from the cluster upgrade channel that only moves the Kubernetes version. AKS applies the updates itself on the `SecurityPatch` and `NodeImage` channels. `Unmanaged` leaves delivery to the operating system's own updater, outside AKS control, and `None` applies nothing at all.

    - PASS: The cluster uses the `SecurityPatch` or `NodeImage` channel.
    - FAIL: The cluster uses `None` or `Unmanaged`, or has no channel configured.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Check the node OS auto-upgrade channel configured on each cluster.

        Returns:
            One report per cluster, passing when the channel is one AKS manages.
        """
        findings = []

        for subscription_id, clusters in aks_client.clusters.items():
            subscription_name = aks_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for cluster in clusters.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_id

                channel = (cluster.node_os_upgrade_channel or "").strip()
                if channel.lower() in MANAGED_NODE_OS_UPGRADE_CHANNELS:
                    report.status = "PASS"
                    report.status_extended = f"Cluster '{cluster.name}' has AKS-managed node OS auto-upgrade channel '{channel}' in subscription '{subscription_name} ({subscription_id})'."
                elif channel:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster '{cluster.name}' has node OS auto-upgrade channel '{channel}', which is not applied by AKS, in subscription '{subscription_name} ({subscription_id})'."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster '{cluster.name}' does not have a node OS auto-upgrade channel configured in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
