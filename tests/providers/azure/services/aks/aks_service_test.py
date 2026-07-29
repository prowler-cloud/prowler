from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.aks.aks_service import AKS, Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


def mock_aks_get_clusters(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "cluster_id-1": Cluster(
                id="cluster_id-1",
                name="cluster_name",
                public_fqdn="public_fqdn",
                private_fqdn="private_fqdn",
                network_policy="network_policy",
                agent_pool_profiles=[],
                location="westeurope",
                rbac_enabled=True,
            )
        }
    }


@patch(
    "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
    new=mock_aks_get_clusters,
)
class Test_AKS_Service:
    def test_get_client(self):
        aks = AKS(set_mocked_azure_provider())
        assert (
            aks.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "ContainerServiceClient"
        )

    def test__get_subscriptions__(self):
        aks = AKS(set_mocked_azure_provider())
        assert aks.subscriptions.__class__.__name__ == "dict"

    def test_get_components(self):
        aks = AKS(set_mocked_azure_provider())
        assert len(aks.clusters) == 1
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].name == "cluster_name"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].public_fqdn
            == "public_fqdn"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].private_fqdn
            == "private_fqdn"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].network_policy
            == "network_policy"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].agent_pool_profiles
            == []
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].location == "westeurope"
        )
        assert aks.clusters[AZURE_SUBSCRIPTION_ID]["cluster_id-1"].rbac_enabled


class Test_AKS_get_clusters:
    def test_get_clusters_no_resource_groups(self):
        mock_cluster = MagicMock()
        mock_cluster.id = "cluster_id-1"
        mock_cluster.name = "cluster_name"
        mock_cluster.fqdn = "public_fqdn"
        mock_cluster.private_fqdn = "private_fqdn"
        mock_cluster.location = "westeurope"
        mock_cluster.kubernetes_version = "1.28.0"
        mock_cluster.network_profile = None
        mock_cluster.agent_pool_profiles = []
        mock_cluster.enable_rbac = False

        mock_client = MagicMock()
        mock_client.managed_clusters.list.return_value = [mock_cluster]

        with patch(
            "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
            return_value={},
        ):
            aks = AKS(set_mocked_azure_provider())

        aks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        aks.resource_groups = None

        result = aks._get_clusters()

        mock_client.managed_clusters.list.assert_called_once()
        mock_client.managed_clusters.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "cluster_id-1" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_clusters_with_resource_group(self):
        mock_cluster = MagicMock()
        mock_cluster.id = "cluster_id-1"
        mock_cluster.name = "cluster_name"
        mock_cluster.fqdn = "public_fqdn"
        mock_cluster.private_fqdn = "private_fqdn"
        mock_cluster.location = "westeurope"
        mock_cluster.kubernetes_version = "1.28.0"
        mock_cluster.network_profile = None
        mock_cluster.agent_pool_profiles = []
        mock_cluster.enable_rbac = False

        mock_client = MagicMock()
        mock_client.managed_clusters.list_by_resource_group.return_value = [
            mock_cluster
        ]

        with patch(
            "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
            return_value={},
        ):
            aks = AKS(set_mocked_azure_provider())

        aks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        aks.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = aks._get_clusters()

        mock_client.managed_clusters.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.managed_clusters.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "cluster_id-1" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_clusters_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with patch(
            "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
            return_value={},
        ):
            aks = AKS(set_mocked_azure_provider())

        aks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        aks.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = aks._get_clusters()

        mock_client.managed_clusters.list_by_resource_group.assert_not_called()
        mock_client.managed_clusters.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_clusters_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.managed_clusters = MagicMock()
        mock_client.managed_clusters.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
            return_value={},
        ):
            aks = AKS(set_mocked_azure_provider())

        aks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        aks.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = aks._get_clusters()

        assert mock_client.managed_clusters.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_clusters_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.managed_clusters = MagicMock()
        mock_client.managed_clusters.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.aks.aks_service.AKS._get_clusters",
            return_value={},
        ):
            aks = AKS(set_mocked_azure_provider())

        aks.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        aks.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        aks._get_clusters()

        mock_client.managed_clusters.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
