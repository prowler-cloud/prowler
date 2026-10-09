from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
import requests

from prowler.providers.fly.exceptions.exceptions import (
    FlyAPIError,
    FlyAuthenticationError,
    FlyRateLimitError,
)
from prowler.providers.fly.lib.service.service import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_AFTER_SECONDS,
    MAX_RETRIES_LIMIT,
    MAX_RETRY_AFTER_SECONDS,
    MAX_TOTAL_RETRY_WAIT_SECONDS,
    FlyService,
    config_value,
    parse_retry_after,
)
from tests.providers.fly.fly_fixtures import (
    APP_NAME,
    ORG_SLUG,
    set_mocked_fly_provider,
)

SERVICE_MODULE = "prowler.providers.fly.lib.service.service"
NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _response(status_code: int, payload=None, headers: dict = None):
    response = mock.MagicMock()
    response.status_code = status_code
    response.headers = headers or {}
    response.json.return_value = payload if payload is not None else {}
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} Error"
        )
    else:
        response.raise_for_status.return_value = None
    return response


def _service(audit_config: dict = None, responses: list = None) -> FlyService:
    provider = set_mocked_fly_provider(audit_config=audit_config)
    http_session = mock.MagicMock()
    if responses:
        http_session.get.side_effect = responses
    provider.session.http_session = http_session
    return FlyService("App", provider)


class Test_parse_retry_after:
    def test_delay_seconds(self):
        assert parse_retry_after("7") == 7

    def test_absent_header_uses_default(self):
        assert parse_retry_after(None) == DEFAULT_RETRY_AFTER_SECONDS

    def test_blank_header_uses_default(self):
        assert parse_retry_after("   ") == DEFAULT_RETRY_AFTER_SECONDS

    def test_unparsable_header_uses_default(self):
        assert parse_retry_after("soon") == DEFAULT_RETRY_AFTER_SECONDS

    def test_non_decimal_digits_use_default(self):
        assert parse_retry_after("\u00b2") == DEFAULT_RETRY_AFTER_SECONDS
        assert parse_retry_after("\u2460") == DEFAULT_RETRY_AFTER_SECONDS

    def test_http_date_in_the_future(self):
        retry_at = (NOW + timedelta(seconds=42)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert parse_retry_after(retry_at, now=NOW) == 42

    def test_http_date_in_the_past_is_zero(self):
        retry_at = (NOW - timedelta(hours=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert parse_retry_after(retry_at, now=NOW) == 0

    def test_http_date_with_numeric_offset(self):
        assert parse_retry_after("Thu, 01 Jan 2026 14:00:30 +0200", now=NOW) == 30

    def test_wait_is_capped(self):
        assert parse_retry_after("99999") == MAX_RETRY_AFTER_SECONDS
        retry_at = (NOW + timedelta(days=2)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        assert parse_retry_after(retry_at, now=NOW) == MAX_RETRY_AFTER_SECONDS


class Test_config_value:
    def test_missing_config_uses_default(self):
        assert config_value(None, "max_retries", 3) == 3

    def test_missing_key_uses_default(self):
        assert config_value({}, "max_retries", 3) == 3

    def test_null_value_uses_default(self):
        assert config_value(
            {"allowed_public_ports": None}, "allowed_public_ports", [80]
        ) == [80]

    def test_explicit_empty_list_is_kept(self):
        assert (
            config_value({"allowed_public_ports": []}, "allowed_public_ports", [80])
            == []
        )

    def test_explicit_zero_is_kept(self):
        assert config_value({"max_retries": 0}, "max_retries", 3) == 0


class Test_FlyService_get:
    def test_success_returns_json(self):
        service = _service(responses=[_response(200, {"apps": [{"name": APP_NAME}]})])

        assert service._get("/apps", params={"org_slug": ORG_SLUG}) == {
            "apps": [{"name": APP_NAME}]
        }
        service._http_session.get.assert_called_once_with(
            "https://api.machines.dev/v1/apps",
            params={"org_slug": ORG_SLUG},
            timeout=30,
        )

    def test_forbidden_is_raised(self):
        service = _service(responses=[_response(403)])

        with pytest.raises(FlyAuthenticationError) as error:
            service._get(f"/apps/{APP_NAME}/machines")

        assert "Access denied (403)" in str(error.value)
        assert f"/apps/{APP_NAME}/machines" in str(error.value)

    def test_unauthorized_is_raised(self):
        service = _service(responses=[_response(401)])

        with pytest.raises(FlyAuthenticationError) as error:
            service._get("/apps")

        assert "Unauthorized (401)" in str(error.value)

    def test_not_found_is_logged_and_returns_none(self):
        service = _service(responses=[_response(404)])

        with mock.patch(f"{SERVICE_MODULE}.logger") as logger_mock:
            assert service._get(f"/apps/{APP_NAME}/volumes") is None

        logger_mock.warning.assert_called_once()
        assert "Not found (404)" in logger_mock.warning.call_args.args[0]

    def test_rate_limit_retries_after_seconds(self):
        service = _service(
            responses=[
                _response(429, headers={"Retry-After": "2"}),
                _response(200, {"apps": []}),
            ]
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            assert service._get("/apps") == {"apps": []}

        sleep_mock.assert_called_once_with(2)

    def test_rate_limit_retries_after_http_date(self):
        retry_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        service = _service(
            responses=[
                _response(429, headers={"Retry-After": retry_at}),
                _response(200, {"apps": []}),
            ]
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            assert service._get("/apps") == {"apps": []}

        sleep_mock.assert_called_once_with(0)

    def test_rate_limit_exhausts_retries(self):
        service = _service(
            audit_config={"max_retries": 1},
            responses=[_response(429), _response(429)],
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyRateLimitError):
                service._get("/apps")

        sleep_mock.assert_called_once_with(DEFAULT_RETRY_AFTER_SECONDS)

    def test_zero_retries_disables_retrying(self):
        service = _service(audit_config={"max_retries": 0}, responses=[_response(429)])

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyRateLimitError):
                service._get("/apps")

        sleep_mock.assert_not_called()

    def test_null_config_uses_default_retries(self):
        provider = set_mocked_fly_provider()
        provider.audit_config = None
        provider.session.http_session = mock.MagicMock()

        service = FlyService("App", provider)

        assert service.audit_config == {}
        assert service.max_retries == DEFAULT_MAX_RETRIES

    def test_null_max_retries_uses_default(self):
        service = _service(audit_config={"max_retries": None})

        assert service.max_retries == DEFAULT_MAX_RETRIES

    def test_max_retries_is_clamped(self):
        assert _service(audit_config={"max_retries": -1}).max_retries == 0
        assert _service(audit_config={"max_retries": 99}).max_retries == (
            MAX_RETRIES_LIMIT
        )
        assert _service(audit_config={"max_retries": "2"}).max_retries == 2

    def test_invalid_max_retries_uses_default(self):
        service = _service(audit_config={"max_retries": "many"})

        with mock.patch(f"{SERVICE_MODULE}.logger") as logger_mock:
            assert service.max_retries == DEFAULT_MAX_RETRIES

        logger_mock.warning.assert_called_once()

    def test_negative_max_retries_still_issues_the_request(self):
        service = _service(
            audit_config={"max_retries": -5}, responses=[_response(200, {"apps": []})]
        )

        assert service._get("/apps") == {"apps": []}

    def test_total_rate_limit_wait_is_bounded(self):
        service = _service(
            audit_config={"max_retries": 10},
            responses=[_response(429, headers={"Retry-After": "300"})] * 11,
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyRateLimitError) as error:
                service._get("/apps")

        assert sleep_mock.call_count == MAX_TOTAL_RETRY_WAIT_SECONDS // 300
        assert f"{MAX_TOTAL_RETRY_WAIT_SECONDS}s of waiting" in str(error.value)

    def test_server_error_raises_api_error(self):
        service = _service(responses=[_response(500)])

        with pytest.raises(FlyAPIError):
            service._get("/apps")

    def test_request_error_retries_then_raises(self):
        service = _service(
            audit_config={"max_retries": 1},
            responses=[
                requests.exceptions.ConnectionError("boom"),
                requests.exceptions.ConnectionError("boom"),
            ],
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyAPIError):
                service._get("/apps")

        sleep_mock.assert_called_once_with(1)


class Test_FlyService_app_scope:
    def test_forbidden_organization_is_logged_and_yields_no_scope(self):
        service = _service(responses=[_response(403)])

        with mock.patch(f"{SERVICE_MODULE}.logger") as logger_mock:
            assert service._app_scope() == []

        logger_mock.error.assert_called_once()
        message = logger_mock.error.call_args.args[0]
        assert message.startswith(
            f"app - Error listing apps for organization {ORG_SLUG}"
        )
        assert "Access denied (403)" in message

    def test_not_found_organization_yields_no_scope(self):
        service = _service(responses=[_response(404)])

        with mock.patch(f"{SERVICE_MODULE}.logger") as logger_mock:
            assert service._app_scope() == []

        logger_mock.warning.assert_called_once()
        logger_mock.error.assert_not_called()

    def test_app_filter_is_applied(self):
        service = _service(
            responses=[
                _response(200, {"apps": [{"name": APP_NAME}, {"name": "other"}]})
            ]
        )
        service.provider.filter_apps = {APP_NAME}

        assert service._app_scope() == [(ORG_SLUG, APP_NAME)]


class Test_FlyService_graphql:
    def test_success_returns_data(self):
        service = _service()
        service._http_session.post.return_value = _response(
            200, {"data": {"organization": {"slug": ORG_SLUG}}}
        )

        assert service._graphql("query { organization { slug } }") == {
            "organization": {"slug": ORG_SLUG}
        }

    @pytest.mark.parametrize("status_code", [401, 403])
    def test_unauthorized_raises_authentication_error(self, status_code):
        service = _service()
        service._http_session.post.return_value = _response(status_code)

        with pytest.raises(FlyAuthenticationError) as error:
            service._graphql("query { organizations { nodes { slug } } }")

        assert str(status_code) in str(error.value)
        service._http_session.post.assert_called_once()

    def test_graphql_errors_raise_api_error(self):
        service = _service()
        service._http_session.post.return_value = _response(
            200, {"errors": [{"message": "Not authorized"}]}
        )

        with pytest.raises(FlyAPIError):
            service._graphql("query { organizations { nodes { slug } } }")

        service._http_session.post.assert_called_once()

    def test_rate_limit_retries_the_same_query_and_variables(self):
        """A throttled read must retain its scope, request body, and timeout."""
        service = _service()
        query = "query($slug: String!) { organization(slug: $slug) { slug } }"
        variables = {"slug": ORG_SLUG}
        data = {"organization": {"slug": ORG_SLUG}}
        service._http_session.post.side_effect = [
            _response(429, headers={"Retry-After": "0"}),
            _response(200, {"data": data}),
        ]

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            assert service._graphql(query, variables) == data

        sleep_mock.assert_called_once_with(0)
        assert (
            service._http_session.post.call_args_list
            == [
                mock.call(
                    service._graphql_url,
                    json={"query": query, "variables": variables},
                    timeout=30,
                )
            ]
            * 2
        )

    @pytest.mark.parametrize(
        "retries, attempts",
        [(0, 1), (1, 2), (3, 4), (10, 11), (99, 11), (-1, 1), (None, 4)],
    )
    def test_rate_limit_exhaustion_obeys_retry_budget(self, retries, attempts):
        """Bound attempts, including zero retries and unvalidated SDK configuration."""
        service = _service(audit_config={"max_retries": retries})
        service._http_session.post.return_value = _response(
            429, headers={"Retry-After": "0"}
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyRateLimitError):
                service._graphql("query { organizations { nodes { slug } } }")

        assert service._http_session.post.call_count == attempts
        assert sleep_mock.call_args_list == [mock.call(0)] * (attempts - 1)

    @pytest.mark.parametrize(
        "retry_after, expected_wait",
        [
            (None, DEFAULT_RETRY_AFTER_SECONDS),
            ("7", 7),
            ("Thu, 01 Jan 2026 12:00:42 GMT", 42),
            ("Thu, 01 Jan 2026 11:59:00 GMT", 0),
            ("99999", 300),
        ],
    )
    def test_rate_limit_honors_bounded_retry_after(self, retry_after, expected_wait):
        """Use the shared seconds/date parser and its per-wait cap."""
        service = _service()
        service._http_session.post.side_effect = [
            _response(429, headers={"Retry-After": retry_after}),
            _response(200, {"data": {"ok": True}}),
        ]

        with (
            mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock,
            mock.patch(f"{SERVICE_MODULE}.datetime") as clock,
        ):
            clock.now.return_value = NOW
            assert service._graphql("query { ok }") == {"ok": True}

        sleep_mock.assert_called_once_with(expected_wait)
        assert service._http_session.post.call_count == 2

    def test_total_rate_limit_wait_is_bounded(self):
        """Repeated long Retry-After values cannot stall one query indefinitely."""
        service = _service(audit_config={"max_retries": 10})
        service._http_session.post.return_value = _response(
            429, headers={"Retry-After": "300"}
        )

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyRateLimitError) as error:
                service._graphql("query { organizations { nodes { slug } } }")

        assert sleep_mock.call_args_list == [mock.call(300), mock.call(300)]
        assert service._http_session.post.call_count == 3
        assert f"{MAX_TOTAL_RETRY_WAIT_SECONDS}s of waiting" in str(error.value)

    @pytest.mark.parametrize("status_code", [404, 500, 503])
    def test_other_http_errors_are_not_retried(self, status_code):
        """GraphQL 404/5xx responses remain API errors, not missing resources."""
        service = _service()
        service._http_session.post.return_value = _response(status_code)

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyAPIError):
                service._graphql("query { organizations { nodes { slug } } }")

        sleep_mock.assert_not_called()
        service._http_session.post.assert_called_once()

    @pytest.mark.parametrize(
        "exception_type",
        [requests.exceptions.Timeout, requests.exceptions.ConnectionError],
    )
    def test_transport_errors_are_not_retried(self, exception_type):
        """Only GraphQL throttling gains retries; transport failures retain behavior."""
        service = _service()
        original = exception_type("Synthetic transport failure")
        service._http_session.post.side_effect = original

        with mock.patch(f"{SERVICE_MODULE}.time.sleep") as sleep_mock:
            with pytest.raises(FlyAPIError) as error:
                service._graphql("query { organizations { nodes { slug } } }")

        assert error.value.original_exception is original
        sleep_mock.assert_not_called()
        service._http_session.post.assert_called_once()
