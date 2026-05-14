from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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

    def test_get_edition_retries_transient_service_unavailable(self):
        from prowler.providers.alibabacloud.services.securitycenter import (
            securitycenter_service as securitycenter_service_module,
        )

        class ServiceUnavailableError(Exception):
            def __init__(self):
                super().__init__("ServiceUnavailable")
                self.code = "ServiceUnavailable"
                self.statusCode = 503

        service = securitycenter_service_module.SecurityCenter.__new__(
            securitycenter_service_module.SecurityCenter
        )
        service.client = MagicMock()
        service.client.describe_version_config.side_effect = [
            ServiceUnavailableError(),
            SimpleNamespace(body=SimpleNamespace(version=5)),
        ]
        service.edition = None
        service.version = None

        with patch.object(
            securitycenter_service_module,
            "sas_models",
            SimpleNamespace(
                DescribeVersionConfigRequest=MagicMock(return_value=object())
            ),
        ):
            service._get_edition()

        assert service.edition == "Advanced"
        assert service.version == 5
        assert service.client.describe_version_config.call_count == 2
