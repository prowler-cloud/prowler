from unittest import mock

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_aks_cluster_defender_enabled:
    def test_no_subscriptions(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled.aks_client",
                new=aks_client,
            ),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled import (
                aks_cluster_defender_enabled,
            )

            aks_client.clusters = {}

            check = aks_cluster_defender_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_pass(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled.aks_client",
                new=aks_client,
            ),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled import (
                aks_cluster_defender_enabled,
            )
            from prowler.providers.azure.services.aks.aks_service import Cluster

            cluster = Cluster(id="/sub/rg/cluster1", name="test-cluster", public_fqdn="test.azmk8s.io", private_fqdn=None, network_policy=None, agent_pool_profiles=[], rbac_enabled=True, location="eastus", defender_enabled=True)
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_defender_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_fail(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled.aks_client",
                new=aks_client,
            ),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_defender_enabled.aks_cluster_defender_enabled import (
                aks_cluster_defender_enabled,
            )
            from prowler.providers.azure.services.aks.aks_service import Cluster

            cluster = Cluster(id="/sub/rg/cluster1", name="test-cluster", public_fqdn="test.azmk8s.io", private_fqdn=None, network_policy=None, agent_pool_profiles=[], rbac_enabled=True, location="eastus", defender_enabled=False)
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_defender_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
