from unittest import mock

import pytest

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_PATH = "prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled"


def build_cluster(node_os_upgrade_channel):
    return Cluster(
        id="/sub/rg/cluster1",
        name="test-cluster",
        public_fqdn="test.azmk8s.io",
        private_fqdn=None,
        network_policy=None,
        agent_pool_profiles=[],
        rbac_enabled=True,
        location="eastus",
        node_os_upgrade_channel=node_os_upgrade_channel,
    )


class Test_aks_cluster_node_os_upgrade_channel_enabled:
    def test_no_subscriptions(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {}

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 0

    @pytest.mark.parametrize(
        "node_os_upgrade_channel",
        ["NodeImage", "SecurityPatch", "nodeimage", "  NodeImage  "],
    )
    def test_pass(self, node_os_upgrade_channel):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            cluster = build_cluster(node_os_upgrade_channel=node_os_upgrade_channel)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' has AKS-managed node OS auto-upgrade channel '{node_os_upgrade_channel.strip()}' in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == "/sub/rg/cluster1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    @pytest.mark.parametrize(
        "node_os_upgrade_channel", ["None", "none", "Unmanaged", "unmanaged"]
    )
    def test_fail_channel_not_applied_by_aks(self, node_os_upgrade_channel):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            cluster = build_cluster(node_os_upgrade_channel=node_os_upgrade_channel)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' has node OS auto-upgrade channel '{node_os_upgrade_channel}', which is not applied by AKS, in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == "/sub/rg/cluster1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    @pytest.mark.parametrize("node_os_upgrade_channel", [None, "", "   "])
    def test_fail_no_channel_configured(self, node_os_upgrade_channel):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            cluster = build_cluster(node_os_upgrade_channel=node_os_upgrade_channel)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' does not have a node OS auto-upgrade channel configured in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )

    def test_unknown_subscription_falls_back_to_id(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            cluster = build_cluster(node_os_upgrade_channel="NodeImage")
            aks_client.subscriptions = {}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Cluster 'test-cluster' has AKS-managed node OS auto-upgrade channel 'NodeImage' in subscription '{AZURE_SUBSCRIPTION_ID} ({AZURE_SUBSCRIPTION_ID})'."
            )

    def test_multiple_clusters_mixed_channels(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_node_os_upgrade_channel_enabled.aks_cluster_node_os_upgrade_channel_enabled import (
                aks_cluster_node_os_upgrade_channel_enabled,
            )

            passing = build_cluster(node_os_upgrade_channel="SecurityPatch")
            failing = build_cluster(node_os_upgrade_channel="Unmanaged")
            failing.id = "/sub/rg/cluster2"
            failing.name = "test-cluster-2"
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {
                AZURE_SUBSCRIPTION_ID: {
                    passing.id: passing,
                    failing.id: failing,
                }
            }

            check = aks_cluster_node_os_upgrade_channel_enabled()
            result = check.execute()
            assert len(result) == 2
            statuses = {report.resource_name: report.status for report in result}
            assert statuses == {"test-cluster": "PASS", "test-cluster-2": "FAIL"}
