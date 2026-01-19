from unittest.mock import patch

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSLSService:
    def test_service(self):
        alibabacloud_provider = set_mocked_alibabacloud_provider()

        with patch(
            "prowler.providers.alibabacloud.services.sls.sls_service.Sls.__init__",
            return_value=None,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_service import Sls

            sls_client = Sls(alibabacloud_provider)
            sls_client.service = "sls"
            sls_client.provider = alibabacloud_provider
            sls_client.regional_clients = {}

            assert sls_client.service == "sls"
            assert sls_client.provider == alibabacloud_provider
