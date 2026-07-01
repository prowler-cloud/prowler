from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRDSService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.rds.rds_service.RDS.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_service import RDS

            rds_client = RDS(alibabacloud_provider)
            rds_client.service = "rds"
            rds_client.provider = alibabacloud_provider
            rds_client.regional_clients = {}

            assert rds_client.service == "rds"
            assert rds_client.provider == alibabacloud_provider

    def test_describe_instances_sets_region_id_on_list_request(self):
        from prowler.providers.alibabacloud.services.rds import (
            rds_service as rds_service_module,
        )

        service = rds_service_module.RDS.__new__(rds_service_module.RDS)
        service.audit_resources = []
        service.instances = []

        request = SimpleNamespace(region_id=None)
        regional_client = MagicMock(region="cn-qingdao")
        regional_client.describe_dbinstances.return_value = SimpleNamespace(
            body=SimpleNamespace(items=None)
        )
        mock_models = SimpleNamespace(
            DescribeDBInstancesRequest=MagicMock(return_value=request)
        )

        with patch.object(rds_service_module, "rds_models", mock_models):
            service._describe_instances(regional_client)

        assert request.region_id == "cn-qingdao"

    def test_describe_db_instance_attribute_sets_region_id(self):
        from prowler.providers.alibabacloud.services.rds import (
            rds_service as rds_service_module,
        )

        service = rds_service_module.RDS.__new__(rds_service_module.RDS)
        request = SimpleNamespace(dbinstance_id=None, region_id=None)
        regional_client = MagicMock(region="cn-qingdao")
        regional_client.describe_dbinstance_attribute.return_value = SimpleNamespace(
            body=SimpleNamespace(items=None)
        )
        mock_models = SimpleNamespace(
            DescribeDBInstanceAttributeRequest=MagicMock(return_value=request)
        )

        with patch.object(rds_service_module, "rds_models", mock_models):
            service._describe_db_instance_attribute(regional_client, "rm-test")

        assert request.dbinstance_id == "rm-test"
        assert request.region_id == "cn-qingdao"
