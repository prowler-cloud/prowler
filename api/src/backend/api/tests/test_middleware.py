from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from api.middleware import APILoggingMiddleware


@pytest.mark.django_db
@patch("logging.getLogger")
def test_api_logging_middleware_logging(mock_logger):
    factory = RequestFactory()

    request = factory.get("/test-path?param1=value1&param2=value2")
    request.method = "GET"

    response = HttpResponse()
    response.status_code = 200

    get_response = MagicMock(return_value=response)

    with patch("api.middleware.extract_auth_info") as mock_extract_auth_info:
        mock_extract_auth_info.return_value = {
            "user_id": "user123",
            "tenant_id": "tenant456",
        }

        with patch("api.middleware.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            middleware = APILoggingMiddleware(get_response)

            with patch("api.middleware.time.time") as mock_time:
                mock_time.side_effect = [1000.0, 1001.0]  # Start time and end time

                middleware(request)

                get_response.assert_called_once_with(request)

                mock_extract_auth_info.assert_called_once_with(request)

                expected_extra = {
                    "user_id": "user123",
                    "tenant_id": "tenant456",
                    "method": "GET",
                    "path": "/test-path",
                    "query_params": {"param1": "value1", "param2": "value2"},
                    "status_code": 200,
                    "duration": 1.0,
                }

                mock_logger.info.assert_called_once_with("", extra=expected_extra)
