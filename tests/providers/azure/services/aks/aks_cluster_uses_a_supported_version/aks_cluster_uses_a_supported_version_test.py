from unittest import mock

import pytest

from prowler.providers.azure.services.aks.aks_service import Cluster
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK_PATH = "prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version"


def build_cluster(kubernetes_version):
    return Cluster(
        id="/sub/rg/cluster1",
        name="test-cluster",
        public_fqdn="test.azmk8s.io",
        private_fqdn=None,
        network_policy=None,
        agent_pool_profiles=[],
        rbac_enabled=True,
        location="eastus",
        kubernetes_version=kubernetes_version,
    )


class Test_aks_cluster_uses_a_supported_version:
    def test_no_subscriptions(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {}
            aks_client.audit_config = {}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 0

    @pytest.mark.parametrize("kubernetes_version", ["1.34", "1.34.10", "1.35.7", "2.0"])
    def test_pass(self, kubernetes_version):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version=kubernetes_version)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {"aks_cluster_oldest_version_supported": "1.34"}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AKS cluster 'test-cluster' is running a supported Kubernetes version {kubernetes_version} in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].resource_id == "/sub/rg/cluster1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "eastus"

    # 1.9 is below 1.34 numerically but above it as a string
    @pytest.mark.parametrize(
        "kubernetes_version", ["1.33", "1.33.5", "1.28", "1.9", "0.9"]
    )
    def test_fail(self, kubernetes_version):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version=kubernetes_version)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {"aks_cluster_oldest_version_supported": "1.34"}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AKS cluster 'test-cluster' is running an unsupported Kubernetes version {kubernetes_version} in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'. The oldest supported version is 1.34."
            )
            assert result[0].resource_name == "test-cluster"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_lowered_baseline(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version="1.31")
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {"aks_cluster_oldest_version_supported": "1.31"}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_unconfigured_baseline(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version="1.33")
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"

    @pytest.mark.parametrize("kubernetes_version", [None, ""])
    def test_cluster_without_version_is_skipped(self, kubernetes_version):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version=kubernetes_version)
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 0

    def test_unparseable_version_is_skipped(self):
        aks_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(f"{CHECK_PATH}.aks_client", new=aks_client),
        ):
            from prowler.providers.azure.services.aks.aks_cluster_uses_a_supported_version.aks_cluster_uses_a_supported_version import (
                aks_cluster_uses_a_supported_version,
            )

            cluster = build_cluster(kubernetes_version="not-a-version")
            aks_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
            aks_client.clusters = {AZURE_SUBSCRIPTION_ID: {cluster.id: cluster}}
            aks_client.audit_config = {}

            check = aks_cluster_uses_a_supported_version()
            result = check.execute()
            assert len(result) == 0
