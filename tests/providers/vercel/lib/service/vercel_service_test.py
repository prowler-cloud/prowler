from unittest import mock

from prowler.providers.vercel.lib.service.service import VercelService


class TestVercelService:
    def test_get_returns_none_and_logs_info_on_expected_403(self):
        service = VercelService.__new__(VercelService)
        service.audit_config = {"max_retries": 0}
        service.service = "security"
        service._team_id = None
        service._base_url = "https://api.vercel.com"

        response = mock.MagicMock()
        response.status_code = 403

        service._http_session = mock.MagicMock()
        service._http_session.get.return_value = response

        with mock.patch(
            "prowler.providers.vercel.lib.service.service.logger"
        ) as logger_mock:
            result = service._get("/v1/security/firewall/config/active")

        assert result is None
        logger_mock.info.assert_called_once_with(
            "security - Access denied for /v1/security/firewall/config/active (403). "
            "This may be caused by plan or permission restrictions."
        )
