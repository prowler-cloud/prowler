from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSecurityCenterService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.securitycenter.securitycenter_service.SecurityCenter.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_service import (
                SecurityCenter,
            )

            securitycenter_client = SecurityCenter(alibabacloud_provider)
            securitycenter_client.service = "securitycenter"
            securitycenter_client.provider = alibabacloud_provider
            securitycenter_client.regional_clients = {}

            assert securitycenter_client.service == "securitycenter"
            assert securitycenter_client.provider == alibabacloud_provider
