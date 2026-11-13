from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_cce_cluster_kubernetes_version:
    def test_cce_k8s_version_pass(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version import (
                cce_cluster_kubernetes_version,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-001",
                    name="cluster-updated",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_kubernetes_version()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "cce-001"
            assert "v1.28" in results[0].status_extended

    def test_cce_k8s_version_fail(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version import (
                cce_cluster_kubernetes_version,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-002",
                    name="cluster-outdated",
                    status="Available",
                    version="v1.21",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_kubernetes_version()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "cce-002"
            assert "below the minimum" in results[0].status_extended

    def test_cce_k8s_version_mixed(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version import (
                cce_cluster_kubernetes_version,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-001",
                    name="cluster-updated",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
                CCECluster(
                    cluster_id="cce-002",
                    name="cluster-outdated",
                    status="Available",
                    version="v1.21",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_kubernetes_version()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_cce_k8s_version_empty(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version import (
                cce_cluster_kubernetes_version,
            )

            cce_client.clusters = []
            cce_client.audited_account = "123456789012"

            check = cce_cluster_kubernetes_version()
            results = check.execute()

            assert len(results) == 0

    def test_cce_k8s_version_no_version(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_kubernetes_version.cce_cluster_kubernetes_version import (
                cce_cluster_kubernetes_version,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-003",
                    name="cluster-no-version",
                    status="Available",
                    version="",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_kubernetes_version()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert "no Kubernetes version" in results[0].status_extended
