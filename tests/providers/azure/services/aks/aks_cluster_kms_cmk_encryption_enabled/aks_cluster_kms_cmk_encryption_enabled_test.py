from unittest import mock

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_PATH = "prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled"


def build_cluster(kms_cmk_encryption_enabled):
    return Cluster(
        id="/sub/rg/cluster1",
        name="test-cluster",
        public_fqdn="test.azmk8s.io",
        private_fqdn=None,
        network_policy=None,
        agent_pool_profiles=[],
        rbac_enabled=True,
        location="eastus",
        kms_cmk_encryption_enabled=kms_cmk_encryption_enabled,
    )


class Test_aks_cluster_kms_cmk_encryption_enabled:
    def test_no_subscriptions(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {}

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            cluster = build_cluster(kms_cmk_encryption_enabled=True)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' encrypts etcd with a customer-managed Key Vault key in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == "/sub/rg/cluster1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    def test_fail(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            cluster = build_cluster(kms_cmk_encryption_enabled=False)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' does not encrypt etcd with a customer-managed Key Vault key in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == "/sub/rg/cluster1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    def test_default_is_fail(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            cluster = Cluster(
                id="/sub/rg/cluster1",
                name="test-cluster",
                public_fqdn="test.azmk8s.io",
                private_fqdn=None,
                network_policy=None,
                agent_pool_profiles=[],
                rbac_enabled=True,
                location="eastus",
            )
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_unknown_subscription_falls_back_to_id(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            cluster = build_cluster(kms_cmk_encryption_enabled=True)
            aks_client.subscriptions = {}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' encrypts etcd with a customer-managed Key Vault key in subscription '{AZURE_SUBSCRIPTION_ID} ({AZURE_SUBSCRIPTION_ID})'."
            )

    def test_multiple_clusters_mixed_encryption(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_kms_cmk_encryption_enabled.aks_cluster_kms_cmk_encryption_enabled import (
                aks_cluster_kms_cmk_encryption_enabled,
            )

            passing = build_cluster(kms_cmk_encryption_enabled=True)
            failing = build_cluster(kms_cmk_encryption_enabled=False)
            failing.id = "/sub/rg/cluster2"
            failing.name = "test-cluster-2"
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {
                AZURE_SUBSCRIPTION_ID: {
                    passing.id: passing,
                    failing.id: failing,
                }
            }

            check = aks_cluster_kms_cmk_encryption_enabled()
            result = check.execute()
            assert len(result) == 2
            statuses = {report.resource_name: report.status for report in result}
            assert statuses == {"test-cluster": "PASS", "test-cluster-2": "FAIL"}
