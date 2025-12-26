from unittest.mock import patch

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
