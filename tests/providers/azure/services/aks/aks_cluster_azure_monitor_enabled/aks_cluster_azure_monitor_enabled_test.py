from importlib import import_module
from unittest import mock
from uuid import uuid4

import pytest

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

CHECK_MODULE = (
    "prowler.providers.azure.services.aks.aks_cluster_azure_monitor_enabled."
    "aks_cluster_azure_monitor_enabled"
)
CHECK_CLIENT_PATCH = f"{CHECK_MODULE}.aks_client"


def get_check_class():
    return import_module(CHECK_MODULE).aks_cluster_azure_monitor_enabled


def build_cluster(azure_monitor_enabled):
    return Cluster(
        id=str(uuid4()),
        name="test-cluster",
        public_fqdn="test.azmk8s.io",
        private_fqdn=None,
        network_policy=None,
        agent_pool_profiles=[],
        rbac_enabled=True,
        location="eastus",
        azure_monitor_enabled=azure_monitor_enabled,
    )


class Test_aks_cluster_azure_monitor_enabled:
    def test_no_subscriptions(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                CHECK_CLIENT_PATCH,
                new=aks_client,
            ),
        ):
            aks_cluster_azure_monitor_enabled = get_check_class()

            aks_client.clusters = {}

            check = aks_cluster_azure_monitor_enabled()
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
                CHECK_CLIENT_PATCH,
                new=aks_client,
            ),
        ):
            aks_cluster_azure_monitor_enabled = get_check_class()

            cluster = build_cluster(azure_monitor_enabled=True)
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_azure_monitor_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Cluster 'test-cluster' has Azure Monitor managed Prometheus metrics enabled."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == cluster.id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    @pytest.mark.parametrize("azure_monitor_enabled", [False, None])
    def test_fail(self, azure_monitor_enabled):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                CHECK_CLIENT_PATCH,
                new=aks_client,
            ),
        ):
            aks_cluster_azure_monitor_enabled = get_check_class()

            cluster = build_cluster(azure_monitor_enabled=azure_monitor_enabled)
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}

            check = aks_cluster_azure_monitor_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Cluster 'test-cluster' does not have Azure Monitor managed Prometheus metrics enabled."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == cluster.id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"
