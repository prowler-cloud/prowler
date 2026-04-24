from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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

    def test_get_alerts_retries_transient_list_project_timeout(self):
        from prowler.providers.alibabacloud.services.sls import (
            sls_service as sls_service_module,
        )

        class ReadTimeoutError(Exception):
            pass

        service = sls_service_module.Sls.__new__(sls_service_module.Sls)
        service.audited_account = "1234567890"
        service.regional_clients = {
            "cn-hangzhou": MagicMock(),
        }
        service.alerts = []

        client = service.regional_clients["cn-hangzhou"]
        client.list_project.side_effect = [
            ReadTimeoutError(
                "HTTPSConnectionPool(host='cn-hangzhou.log.aliyuncs.com', port=443): Read timed out. (read timeout=10.0)"
            ),
            SimpleNamespace(
                body=SimpleNamespace(
                    projects=[
                        SimpleNamespace(project_name="project-1"),
                    ]
                )
            ),
        ]
        client.list_alerts.return_value = SimpleNamespace(
            body=SimpleNamespace(results=[])
        )

        with patch.object(
            sls_service_module,
            "sls_models",
            SimpleNamespace(
                ListProjectRequest=MagicMock(return_value=object()),
                ListAlertsRequest=MagicMock(return_value=object()),
            ),
        ):
            service._get_alerts()

        assert client.list_project.call_count == 2
