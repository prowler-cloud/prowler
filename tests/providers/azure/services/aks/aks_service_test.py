from unittest.mock import patch

from prowler.providers.azure.services.aks.aks_service import AKS, Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


def mock_aks_get_clusters(_):
    return {
        AZURE_SUBSCRIPTION: {
            "cluster_id-1": Cluster(
                name="cluster_name",
                public_fqdn="public_fqdn",
                private_fqdn="private_fqdn",
                network_policy="network_policy",
                agent_pool_profiles=[],
                rbac_enabled=True,
            )
        }
    }


@patch(
    "prowler.providers.azure.services.aks.aks_service.AKS.__get_clusters__",
    new=mock_aks_get_clusters,
)
class Test_AppInsights_Service:
    def test__get_client__(self):
        aks = AKS(set_mocked_azure_provider())
        assert (
            aks.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "ContainerServiceClient"
        )

    def test__get_subscriptions__(self):
        aks = AKS(set_mocked_azure_provider())
        assert aks.subscriptions.__class__.__name__ == "dict"

    def test__get_components__(self):
        aks = AKS(set_mocked_azure_provider())
        assert len(aks.clusters) == 1
        assert aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].name == "cluster_name"
        assert (
            aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].public_fqdn
            == "public_fqdn"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].private_fqdn
            == "private_fqdn"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].network_policy
            == "network_policy"
        )
        assert (
            aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].agent_pool_profiles == []
        )
        assert aks.clusters[AZURE_SUBSCRIPTION]["cluster_id-1"].rbac_enabled
