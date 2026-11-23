from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aks.aks_client import aks_client


class aks_cluster_kms_cmk_encryption_enabled(Check):
    """
    Ensure AKS clusters encrypt Kubernetes secrets in etcd with a customer-managed key.

    Azure Key Vault KMS makes the API server envelope-encrypt every Kubernetes Secret with a key held in the customer's Azure Key Vault before writing it to etcd. The AKS control plane, etcd included, is operated by Microsoft, so without a customer-managed key the subscription owner has no independent control over secrets at rest: no way to revoke access, no record of key use in their own tenant, and no basis for a customer-managed key assertion to an auditor.

    - PASS: The cluster encrypts etcd with a customer-managed Key Vault key.
    - FAIL: The cluster does not use a customer-managed Key Vault key, including clusters relying on AKS platform-managed keys.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Check whether Azure Key Vault KMS etcd encryption is enabled on each cluster.

        Returns:
            One report per cluster, passing when a customer-managed Key Vault key is in use.
        """
        findings = []

        for subscription_id, clusters in aks_client.clusters.items():
            subscription_name = aks_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for cluster in clusters.values():
                report = Check_Report_Azure(metadata=self.metadata(), resource=cluster)
                report.subscription = subscription_id

                if cluster.kms_cmk_encryption_enabled:
                    report.status = "PASS"
                    report.status_extended = f"Cluster '{cluster.name}' encrypts etcd with a customer-managed Key Vault key in subscription '{subscription_name} ({subscription_id})'."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Cluster '{cluster.name}' does not encrypt etcd with a customer-managed Key Vault key in subscription '{subscription_name} ({subscription_id})'."

                findings.append(report)

        return findings
