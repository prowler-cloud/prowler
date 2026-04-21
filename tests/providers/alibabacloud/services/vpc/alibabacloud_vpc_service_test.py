from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestVPCService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.vpc.vpc_service.VPC.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.vpc.vpc_service import VPC

            vpc_client = VPC(alibabacloud_provider)
            vpc_client.service = "vpc"
            vpc_client.provider = alibabacloud_provider
            vpc_client.regional_clients = {}

            assert vpc_client.service == "vpc"
            assert vpc_client.provider == alibabacloud_provider
