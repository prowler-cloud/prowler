from datetime import datetime, timedelta, timezone
from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestCSKubernetesClusterCheckRecent:
    def test_cluster_check_stale_fails(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"
        cs_client.audit_config = {"max_cluster_check_days": 7}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_cluster_check_recent.cs_kubernetes_cluster_check_recent.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_cluster_check_recent.cs_kubernetes_cluster_check_recent import (
                cs_kubernetes_cluster_check_recent,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c1",
                name="c1",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                last_check_time=datetime.now(timezone.utc) - timedelta(days=10),
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_cluster_check_recent()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_cluster_check_recent_passes(self):
        cs_client = mock.MagicMock()
        cs_client.audited_account = "1234567890"
        cs_client.audit_config = {"max_cluster_check_days": 7}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.cs.cs_kubernetes_cluster_check_recent.cs_kubernetes_cluster_check_recent.cs_client",
                new=cs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.cs.cs_kubernetes_cluster_check_recent.cs_kubernetes_cluster_check_recent import (
                cs_kubernetes_cluster_check_recent,
            )
            from prowler.providers.alibabacloud.services.cs.cs_service import Cluster

            cluster = Cluster(
                id="c2",
                name="c2",
                region="cn-hangzhou",
                cluster_type="k8s",
                state="running",
                last_check_time=datetime.now(timezone.utc) - timedelta(days=3),
            )
            cs_client.clusters = [cluster]

            check = cs_kubernetes_cluster_check_recent()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
