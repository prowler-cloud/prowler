from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


class Test_aks_cluster_rbac_enabled:
    def test_aks_no_subscriptions(self):
        aks_client = mock.MagicMock
        aks_client.clusters = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled import (
                aks_cluster_rbac_enabled,
            )

            check = aks_cluster_rbac_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_aks_subscription_empty(self):
        aks_client = mock.MagicMock
        aks_client.clusters = {AZURE_SUBSCRIPTION: {}}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled import (
                aks_cluster_rbac_enabled,
            )

            check = aks_cluster_rbac_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_aks_cluster_rbac_enabled(self):
        aks_client = mock.MagicMock
        cluster_id = str(uuid4())
        aks_client.clusters = {
            AZURE_SUBSCRIPTION: {
                cluster_id: Cluster(
                    name="cluster_name",
                    public_fqdn="public_fqdn",
                    private_fqdn=None,
                    network_policy="network_policy",
                    agent_pool_profiles=[mock.MagicMock(enable_node_public_ip=False)],
                    rbac_enabled=True,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled import (
                aks_cluster_rbac_enabled,
            )

            check = aks_cluster_rbac_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"RBAC is enabled for cluster 'cluster_name' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_name == "cluster_name"
            assert result[0].resource_id == cluster_id
            assert result[0].subscription == AZURE_SUBSCRIPTION

    def test_aks_rbac_not_enabled(self):
        aks_client = mock.MagicMock
        cluster_id = str(uuid4())
        aks_client.clusters = {
            AZURE_SUBSCRIPTION: {
                cluster_id: Cluster(
                    name="cluster_name",
                    public_fqdn="public_fqdn",
                    private_fqdn=None,
                    network_policy="network_policy",
                    agent_pool_profiles=[mock.MagicMock(enable_node_public_ip=False)],
                    rbac_enabled=False,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled.aks_client",
            new=aks_client,
        ):
            from prowler.providers.azure.services.aks.aks_cluster_rbac_enabled.aks_cluster_rbac_enabled import (
                aks_cluster_rbac_enabled,
            )

            check = aks_cluster_rbac_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"RBAC is not enabled for cluster 'cluster_name' in subscription '{AZURE_SUBSCRIPTION}'."
            )
            assert result[0].resource_name == "cluster_name"
            assert result[0].resource_id == cluster_id
            assert result[0].subscription == AZURE_SUBSCRIPTION
