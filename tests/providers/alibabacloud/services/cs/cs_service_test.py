from unittest.mock import patch

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
