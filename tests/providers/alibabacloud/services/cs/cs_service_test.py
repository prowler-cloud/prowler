from datetime import datetime, timezone
from threading import Lock
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestCSService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.cs.cs_service.CS.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.cs.cs_service import CS

            cs_client = CS(alibabacloud_provider)
            cs_client.service = "cs"
            cs_client.provider = alibabacloud_provider
            cs_client.regional_clients = {}

            assert cs_client.service == "cs"
            assert cs_client.provider == alibabacloud_provider

    def test_get_cluster_detail_uses_requestless_sdk_and_parses_response(self):
        from prowler.providers.alibabacloud.services.cs import (
            cs_service as cs_service_module,
        )

        service = cs_service_module.CS.__new__(cs_service_module.CS)
        regional_client = MagicMock(region="cn-hangzhou")
        regional_client.describe_cluster_detail.return_value = SimpleNamespace(
            body=SimpleNamespace(
                meta_data='{"AuditProjectName":"audit-project","Addons":[{"name":"terway","disabled":false}],"RBACEnabled":"true"}',
                parameters={"authorization_mode": "RBAC", "endpoint_public": "false"},
                master_url="",
            )
        )

        with patch.object(cs_service_module, "cs_models", SimpleNamespace()):
            result = service._get_cluster_detail(regional_client, "cluster-id")

        regional_client.describe_cluster_detail.assert_called_once_with("cluster-id")
        assert result == {
            "meta_data": {
                "AuditProjectName": "audit-project",
                "Addons": [{"name": "terway", "disabled": False}],
                "RBACEnabled": "true",
            },
            "parameters": {
                "authorization_mode": "RBAC",
                "endpoint_public": "false",
            },
            "master_url": "",
        }

    def test_get_last_cluster_check_uses_list_cluster_checks(self):
        from prowler.providers.alibabacloud.services.cs import (
            cs_service as cs_service_module,
        )

        service = cs_service_module.CS.__new__(cs_service_module.CS)
        regional_client = MagicMock(region="cn-hangzhou")
        request = object()
        most_recent = datetime(2026, 4, 22, tzinfo=timezone.utc)
        older = datetime(2026, 4, 20, tzinfo=timezone.utc)
        regional_client.list_cluster_checks.return_value = SimpleNamespace(
            body=SimpleNamespace(
                checks=[
                    SimpleNamespace(status="Succeeded", finished_at=older),
                    SimpleNamespace(status="Failed", finished_at=None),
                    SimpleNamespace(status="Succeeded", finished_at=most_recent),
                ]
            )
        )
        mock_models = SimpleNamespace(
            ListClusterChecksRequest=MagicMock(return_value=request)
        )

        with patch.object(cs_service_module, "cs_models", mock_models):
            result = service._get_last_cluster_check(regional_client, "cluster-id")

        mock_models.ListClusterChecksRequest.assert_called_once_with()
        regional_client.list_cluster_checks.assert_called_once_with(
            "cluster-id", request
        )
        assert result == most_recent

    def test_describe_clusters_populates_clusters_with_sdk_6_1_0_shape(self):
        from prowler.providers.alibabacloud.services.cs import (
            cs_service as cs_service_module,
        )

        service = cs_service_module.CS.__new__(cs_service_module.CS)
        service.audit_resources = []
        service.clusters = []
        service.regional_clients = {}
        service._cluster_ids_lock = Lock()
        service._seen_cluster_ids = set()

        describe_clusters_request = object()
        describe_node_pools_request = object()
        list_checks_request = object()
        regional_client = MagicMock(region="cn-hangzhou")
        regional_client.describe_clusters_v1.return_value = SimpleNamespace(
            body=SimpleNamespace(
                clusters=[
                    SimpleNamespace(
                        cluster_id="c-1",
                        name="test-cluster",
                        cluster_type="ManagedKubernetes",
                        state="running",
                    )
                ]
            )
        )
        regional_client.describe_cluster_detail.return_value = SimpleNamespace(
            body=SimpleNamespace(
                meta_data='{"AuditProjectName":"audit-project","Addons":[{"name":"terway","disabled":false}],"RBACEnabled":"true"}',
                parameters={"authorization_mode": "RBAC"},
                master_url="",
            )
        )
        regional_client.describe_cluster_node_pools.return_value = SimpleNamespace(
            body=SimpleNamespace(
                nodepools=[
                    SimpleNamespace(kubernetes_config=SimpleNamespace(cms_enabled=True))
                ]
            )
        )
        regional_client.list_cluster_checks.return_value = SimpleNamespace(
            body=SimpleNamespace(
                checks=[
                    SimpleNamespace(
                        status="Succeeded",
                        finished_at=datetime(2026, 4, 22, tzinfo=timezone.utc),
                    )
                ]
            )
        )
        mock_models = SimpleNamespace(
            DescribeClustersV1Request=MagicMock(return_value=describe_clusters_request),
            DescribeClusterNodePoolsRequest=MagicMock(
                return_value=describe_node_pools_request
            ),
            ListClusterChecksRequest=MagicMock(return_value=list_checks_request),
        )

        with patch.object(cs_service_module, "cs_models", mock_models):
            service._describe_clusters(regional_client)

        regional_client.describe_clusters_v1.assert_called_once_with(
            describe_clusters_request
        )
        regional_client.describe_cluster_detail.assert_called_once_with("c-1")
        regional_client.describe_cluster_node_pools.assert_called_once_with(
            "c-1", describe_node_pools_request
        )
        regional_client.list_cluster_checks.assert_called_once_with(
            "c-1", list_checks_request
        )
        assert len(service.clusters) == 1
        cluster = service.clusters[0]
        assert cluster.id == "c-1"
        assert cluster.log_service_enabled is True
        assert cluster.cloudmonitor_enabled is True
        assert cluster.rbac_enabled is True
        assert cluster.network_policy_enabled is True
        assert cluster.eni_multiple_ip_enabled is True
        assert cluster.private_cluster_enabled is True

    def test_describe_clusters_uses_cluster_region_and_deduplicates(self):
        from prowler.providers.alibabacloud.services.cs import (
            cs_service as cs_service_module,
        )

        service = cs_service_module.CS.__new__(cs_service_module.CS)
        service.audit_resources = []
        service.clusters = []
        service._cluster_ids_lock = Lock()
        service._seen_cluster_ids = set()

        list_request = object()
        node_pools_request = object()
        checks_request = object()
        canonical_client = MagicMock(region="ap-southeast-1")
        duplicate_client = MagicMock(region="cn-shenzhen")
        service.regional_clients = {
            "ap-southeast-1": canonical_client,
            "cn-shenzhen": duplicate_client,
        }

        for client in (canonical_client, duplicate_client):
            client.describe_clusters_v1.return_value = SimpleNamespace(
                body=SimpleNamespace(
                    clusters=[
                        SimpleNamespace(
                            cluster_id="c-1",
                            name="test-cluster",
                            cluster_type="ManagedKubernetes",
                            state="running",
                            region_id="ap-southeast-1",
                        )
                    ]
                )
            )

        canonical_client.describe_cluster_detail.return_value = SimpleNamespace(
            body=SimpleNamespace(
                meta_data='{"AuditProjectName":"audit-project","Addons":[]}',
                parameters={"authorization_mode": "RBAC"},
                master_url="",
            )
        )
        canonical_client.describe_cluster_node_pools.return_value = SimpleNamespace(
            body=SimpleNamespace(nodepools=[])
        )
        canonical_client.list_cluster_checks.return_value = SimpleNamespace(
            body=SimpleNamespace(checks=[])
        )

        mock_models = SimpleNamespace(
            DescribeClustersV1Request=MagicMock(return_value=list_request),
            DescribeClusterNodePoolsRequest=MagicMock(return_value=node_pools_request),
            ListClusterChecksRequest=MagicMock(return_value=checks_request),
        )

        with patch.object(cs_service_module, "cs_models", mock_models):
            service._describe_clusters(duplicate_client)
            service._describe_clusters(canonical_client)

        assert len(service.clusters) == 1
        assert service.clusters[0].region == "ap-southeast-1"
        canonical_client.describe_cluster_detail.assert_called_once_with("c-1")
        duplicate_client.describe_cluster_detail.assert_not_called()

    def test_check_cluster_addons_handles_null_addons_without_logging_error(self):
        from prowler.providers.alibabacloud.services.cs import (
            cs_service as cs_service_module,
        )

        service = cs_service_module.CS.__new__(cs_service_module.CS)

        with patch.object(cs_service_module.logger, "error") as logger_error:
            result = service._check_cluster_addons(
                {"meta_data": {"Addons": None}},
                "cn-hangzhou",
            )

        assert result == {
            "dashboard_enabled": False,
            "network_policy_enabled": False,
            "eni_multiple_ip_enabled": False,
        }
        logger_error.assert_not_called()

    def test_check_public_access_handles_false_string(self):
        from prowler.providers.alibabacloud.services.cs.cs_service import CS

        service = CS.__new__(CS)

        result = service._check_public_access(
            {"parameters": {"endpoint_public": "false"}, "master_url": ""},
            "cn-hangzhou",
        )

        assert result is False
