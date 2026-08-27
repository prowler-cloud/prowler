from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.lib.logger import logger
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_uses_a_supported_version(Check):
    """
    Ensure AKS clusters run a supported Kubernetes version.

    AKS gives community support to the latest generally available minor version and the two before it, so older versions stop receiving security patches. The baseline is configurable through `aks_cluster_oldest_version_supported`, which can be lowered for clusters enrolled in long-term support.

    - PASS: The cluster runs a Kubernetes version at or above the baseline.
    - FAIL: The cluster runs a Kubernetes version below the baseline.
    """

    def execute(self) -> list[Check_Report_Azure]:
        findings = []

        aks_cluster_oldest_version_supported = aks_client.audit_config.get(
            "aks_cluster_oldest_version_supported", "1.34"
        )
        oldest_supported_version = tuple(
            map(int, aks_cluster_oldest_version_supported.split(".")[:2])
        )

        for subscription_id, clusters in aks_client.clusters.items():
            subscription_name = aks_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for cluster in clusters.values():
                if not cluster.kubernetes_version:
                    continue

                try:
                    cluster_version = tuple(
                        map(int, cluster.kubernetes_version.split(".")[:2])
                    )
                except ValueError:
                    logger.error(
                        f"Subscription ID: {subscription_id} -- Cluster {cluster.name} has an unparseable Kubernetes version: {cluster.kubernetes_version}"
                    )
                    continue

                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_id

                if cluster_version < oldest_supported_version:
                    report.status = "FAIL"
                    report.status_extended = f"AKS cluster '{cluster.name}' is running an unsupported Kubernetes version {cluster.kubernetes_version} in subscription '{subscription_name} ({subscription_id})'. The oldest supported version is {aks_cluster_oldest_version_supported}."
                else:
                    report.status = "PASS"
                    report.status_extended = f"AKS cluster '{cluster.name}' is running a supported Kubernetes version {cluster.kubernetes_version} in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
