from unittest import mock

from okta.http_client import HTTPClient

from prowler.providers.okta.lib.service.rate_limiter import OktaRateLimiter
from prowler.providers.okta.lib.service.service import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    OktaService,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _build_service(audit_config: dict = None, rate_limiter=None):
    """Instantiate OktaService with the SDK client patched, returning the
    config dict that was handed to ``OktaSDKClient``."""
    provider = set_mocked_okta_provider(
        audit_config=audit_config, rate_limiter=rate_limiter
    )
    with mock.patch(
        "prowler.providers.okta.lib.service.service.OktaSDKClient"
    ) as mocked_client_cls:
        OktaService("test", provider)
    return mocked_client_cls.call_args.args[0]


class Test_OktaService_set_client:
    def test_defaults_applied_when_audit_config_empty(self):
        config = _build_service(audit_config={})

        assert config["rateLimit"] == {"maxRetries": DEFAULT_MAX_RETRIES}
        assert config["requestTimeout"] == DEFAULT_REQUEST_TIMEOUT

    def test_defaults_applied_when_audit_config_none(self):
        # set_mocked_okta_provider coerces None to {}, but the helper also
        # guards against a None audit_config defensively.
        config = _build_service(audit_config=None)

        assert config["rateLimit"] == {"maxRetries": DEFAULT_MAX_RETRIES}
        assert config["requestTimeout"] == DEFAULT_REQUEST_TIMEOUT

    def test_audit_config_values_override_defaults(self):
        config = _build_service(
            audit_config={"okta_max_retries": 9, "okta_request_timeout": 120}
        )

        assert config["rateLimit"] == {"maxRetries": 9}
        assert config["requestTimeout"] == 120

    def test_retries_disabled_with_zero(self):
        config = _build_service(audit_config={"okta_max_retries": 0})

        assert config["rateLimit"] == {"maxRetries": 0}

    def test_preserves_session_sdk_config_keys(self):
        config = _build_service(audit_config={})

        # The rate-limit settings are layered on top of the shared session
        # config, so the credential keys must remain intact.
        assert config["orgUrl"] == "https://acme.okta.com"
        assert config["authorizationMode"] == "PrivateKey"
        assert config["clientId"]
        assert config["privateKey"]
        assert config["dpopEnabled"] is True

    def test_no_http_client_injected_without_limiter(self):
        config = _build_service(audit_config={})

        assert "httpClient" not in config

    def test_throttled_http_client_injected_with_limiter(self):
        limiter = OktaRateLimiter(4)
        config = _build_service(audit_config={}, rate_limiter=limiter)

        # The SDK instantiates the class itself, so a throttled HTTPClient
        # subclass must be injected (not an instance).
        http_client_cls = config["httpClient"]
        assert isinstance(http_client_cls, type)
        assert issubclass(http_client_cls, HTTPClient)
