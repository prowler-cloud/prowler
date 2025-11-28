from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestCSKubernetesRBACEnabled:
    def test_rbac_disabled_fails(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_rbac_enabled.cs_kubernetes_rbac_enabled.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_rbac_enabled.cs_kubernetes_rbac_enabled import (
                cs_kubernetes_rbac_enabled,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c1",
                name="c1",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                rbac_enabled=False,
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_rbac_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_rbac_enabled_passes(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_rbac_enabled.cs_kubernetes_rbac_enabled.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_rbac_enabled.cs_kubernetes_rbac_enabled import (
                cs_kubernetes_rbac_enabled,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c2",
                name="c2",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                rbac_enabled=True,
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_rbac_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
