from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestCSKubernetesPrivateClusterEnabled:
    def test_public_cluster_fails(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"
        cs_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_private_cluster_enabled.cs_kubernetes_private_cluster_enabled.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_private_cluster_enabled.cs_kubernetes_private_cluster_enabled import (
                cs_kubernetes_private_cluster_enabled,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c1",
                name="public",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                private_cluster_enabled=False,
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_private_cluster_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "public API endpoint" in result[0].status_extended

    def test_private_cluster_passes(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"
        cs_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_private_cluster_enabled.cs_kubernetes_private_cluster_enabled.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_private_cluster_enabled.cs_kubernetes_private_cluster_enabled import (
                cs_kubernetes_private_cluster_enabled,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c2",
                name="private",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                private_cluster_enabled=True,
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_private_cluster_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "private cluster" in result[0].status_extended
