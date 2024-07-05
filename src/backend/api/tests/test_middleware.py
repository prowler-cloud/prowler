from unittest.mock import patch, Mock, ANY


@patch("logging.getLogger")
def test_api_logger_middleware(mock_get_logger, client):
    mock_logger = Mock()
    mock_get_logger.side_effect = lambda name: mock_logger if name == "api" else Mock()
    request_method = "GET"
    request_path = "/this_path_does_not_exist"
    api_logger = "api"

    response = getattr(client, request_method.lower())(request_path)

    mock_get_logger.assert_any_call(api_logger)
    mock_logger.info.assert_called_once_with(
        "",
        extra={
            "method": request_method,
            "path": request_path,
            "query_params": {},
            "status_code": response.status_code,
            "duration": ANY,
        },
    )

    assert isinstance(mock_logger.info.call_args[1]["extra"]["duration"], float)
