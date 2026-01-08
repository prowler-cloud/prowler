from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRAMService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.ram.ram_service.RAM.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.ram.ram_service import RAM

            ram_client = RAM(alibabacloud_provider)
            ram_client.service = "ram"
            ram_client.provider = alibabacloud_provider
            ram_client.regional_clients = {}

            assert ram_client.service == "ram"
            assert ram_client.provider == alibabacloud_provider
