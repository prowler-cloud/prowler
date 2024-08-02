from unittest.mock import patch, Mock, ANY

import pytest
from django.http import HttpResponse

from api.middleware import extract_tenant_id, TenantMiddleware


@pytest.mark.django_db
@patch("logging.getLogger")
def test_api_logger_middleware(mock_get_logger, client):
    mock_logger = Mock()
    mock_get_logger.side_effect = lambda name: mock_logger if name == "api" else Mock()
    request_method = "GET"
    request_path = "/this_path_does_not_exist"
    tenant_id = "12646005-9067-4d2a-a098-8bb378604362"
    api_logger = "api"

    response = getattr(client, request_method.lower())(
        request_path, headers={"X-Tenant-ID": tenant_id}
    )

    mock_get_logger.assert_any_call(api_logger)
    mock_logger.info.assert_called_once_with(
        "",
        extra={
            "method": request_method,
            "path": request_path,
            "query_params": {},
            "status_code": response.status_code,
            "duration": ANY,
            "tenant_id": tenant_id,
        },
    )

    assert isinstance(mock_logger.info.call_args[1]["extra"]["duration"], float)


@patch("api.middleware.TenantMiddleware.set_tenant_id_in_session")
def test_tenant_middleware(mock_set_tenant, client):
    tenant_id = "12646005-9067-4d2a-a098-8bb378604362"
    tenant_header = {"X-Tenant-ID": tenant_id}

    response = client.get("/testing", headers=tenant_header)

    mock_set_tenant.assert_called_once_with(tenant_id)
    assert isinstance(response, HttpResponse)


@patch("api.middleware.connection.cursor")
def test_tenant_middleware_set_tenant_id_in_session(cursor_mock):
    cursor_mock.return_value.__enter__.return_value = cursor_mock
    cursor_mock.execute.return_value = None

    tenant_id_postgres_variable = "api.tenant_id"
    tenant_id = "12646005-9067-4d2a-a098-8bb378604362"
    tenant_middleware = TenantMiddleware(Mock())

    tenant_middleware.set_tenant_id_in_session(tenant_id)

    cursor_mock.execute.assert_called_once_with(
        f"SET {tenant_id_postgres_variable} = %s", [tenant_id]
    )


def test_extract_tenant_id():
    mock_request = Mock()
    extract_tenant_id(mock_request)

    mock_request.headers.get.assert_called_once_with("X-Tenant-ID")
