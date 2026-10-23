from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class Test_cce_cluster_public_endpoint:
    def test_cce_public_endpoint_pass(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint import (
                cce_cluster_public_endpoint,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-001",
                    name="cluster-private",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_public_endpoint()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "PASS"
            assert results[0].resource_id == "cce-001"
            assert "does not have a public" in results[0].status_extended

    def test_cce_public_endpoint_fail(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint import (
                cce_cluster_public_endpoint,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-002",
                    name="cluster-public",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=True,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_public_endpoint()
            results = check.execute()

            assert len(results) == 1
            assert results[0].status == "FAIL"
            assert results[0].resource_id == "cce-002"
            assert "public API endpoint" in results[0].status_extended

    def test_cce_public_endpoint_mixed(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_service import (
                CCECluster,
            )
            from prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint import (
                cce_cluster_public_endpoint,
            )

            cce_client.clusters = [
                CCECluster(
                    cluster_id="cce-001",
                    name="cluster-private",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=False,
                    region="la-south-2",
                ),
                CCECluster(
                    cluster_id="cce-002",
                    name="cluster-public",
                    status="Available",
                    version="v1.28",
                    has_public_endpoint=True,
                    region="la-south-2",
                ),
            ]
            cce_client.audited_account = "123456789012"

            check = cce_cluster_public_endpoint()
            results = check.execute()

            assert len(results) == 2
            assert results[0].status == "PASS"
            assert results[1].status == "FAIL"

    def test_cce_public_endpoint_empty(self):
        cce_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint.cce_client",
                new=cce_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.cce.cce_cluster_public_endpoint.cce_cluster_public_endpoint import (
                cce_cluster_public_endpoint,
            )

            cce_client.clusters = []
            cce_client.audited_account = "123456789012"

            check = cce_cluster_public_endpoint()
            results = check.execute()

            assert len(results) == 0
