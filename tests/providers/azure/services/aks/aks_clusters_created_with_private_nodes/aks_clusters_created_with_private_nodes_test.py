from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_aks_clusters_created_with_private_nodes:
    def test_aks_no_subscriptions(self):
        aks_client = mock.MagicMock
        aks_client.clusters = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes import (
                aks_clusters_created_with_private_nodes,
            )

            check = aks_clusters_created_with_private_nodes()
            result = check.execute()
            assert len(result) == 0

    def test_aks_subscription_empty(self):
        aks_client = mock.MagicMock
        aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes import (
                aks_clusters_created_with_private_nodes,
            )

            check = aks_clusters_created_with_private_nodes()
            result = check.execute()
            assert len(result) == 0

    def test_aks_cluster_no_private_nodes(self):
        aks_client = mock.MagicMock
        cluster_id = str(uuid4())
        aks_client.clusters = {
            AZURE_SUBSCRIPTION_ID: {
                cluster_id: Cluster(
                    name="cluster_name",
                    public_fqdn="public_fqdn",
                    private_fqdn="",
                    network_policy="network_policy",
                    agent_pool_profiles=[mock.MagicMock(enable_node_public_ip=True)],
                    location="westeurope",
                    rbac_enabled=True,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes import (
                aks_clusters_created_with_private_nodes,
            )

            check = aks_clusters_created_with_private_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster 'cluster_name' was not created with private nodes in subscription '{AZURE_SUBSCRIPTION_ID}'"
            )
            assert result[0].resource_id == cluster_id
            assert result[0].resource_name == "cluster_name"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"

    def test_aks_cluster_private_nodes(self):
        aks_client = mock.MagicMock
        cluster_id = str(uuid4())
        aks_client.clusters = {
            AZURE_SUBSCRIPTION_ID: {
                cluster_id: Cluster(
                    name="cluster_name",
                    public_fqdn="public_fqdn",
                    private_fqdn="private_fqdn",
                    network_policy="network_policy",
                    agent_pool_profiles=[mock.MagicMock(enable_node_public_ip=False)],
                    location="westeurope",
                    rbac_enabled=True,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes import (
                aks_clusters_created_with_private_nodes,
            )

            check = aks_clusters_created_with_private_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster 'cluster_name' was created with private nodes in subscription '{AZURE_SUBSCRIPTION_ID}'"
            )
            assert result[0].resource_id == cluster_id
            assert result[0].resource_name == "cluster_name"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"

    def test_aks_cluster_public_and_private_nodes(self):
        aks_client = mock.MagicMock
        cluster_id = str(uuid4())
        aks_client.clusters = {
            AZURE_SUBSCRIPTION_ID: {
                cluster_id: Cluster(
                    name="cluster_name",
                    public_fqdn="public_fqdn",
                    private_fqdn="private_fqdn",
                    network_policy="network_policy",
                    agent_pool_profiles=[
                        mock.MagicMock(enable_node_public_ip=False),
                        mock.MagicMock(enable_node_public_ip=True),
                        mock.MagicMock(enable_node_public_ip=False),
                    ],
                    location="westeurope",
                    rbac_enabled=True,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_clusters_created_with_private_nodes.aks_clusters_created_with_private_nodes import (
                aks_clusters_created_with_private_nodes,
            )

            check = aks_clusters_created_with_private_nodes()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster 'cluster_name' was not created with private nodes in subscription '{AZURE_SUBSCRIPTION_ID}'"
            )
            assert result[0].resource_id == cluster_id
            assert result[0].resource_name == "cluster_name"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "westeurope"
