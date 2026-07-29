import asyncio
from typing import TYPE_CHECKING

from okta.client import Client as OktaSDKClient

from prowler.providers.okta.lib.service.rate_limiter import build_throttled_http_client
from prowler.providers.okta.models import OktaSession

if TYPE_CHECKING:
    from prowler.providers.okta.okta_provider import OktaProvider

# Okta API rate-limit handling. The okta-sdk-python `Client` already backs off
# on HTTP 429 by sleeping until the `X-Rate-Limit-Reset` window before retrying,
# but it only does so `maxRetries` times (SDK default 2). On busy orgs that is
# too few and requests fail with partial data, so we raise it. See config.yaml
# (`okta_max_retries` / `okta_request_timeout`) for the user-facing knobs and the
# rationale behind the 300s timeout default.
DEFAULT_MAX_RETRIES = 5
DEFAULT_REQUEST_TIMEOUT = 300


class OktaService:
    """Base class for Okta service implementations.

    Wraps the async okta-sdk-python `Client` so that subclasses can stay
    synchronous like the other Prowler providers. The SDK auto-refreshes
    the OAuth access token; nothing to manage here.
    """

    def __init__(self, service: str, provider: "OktaProvider"):
        self.provider = provider
        self.service = service
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.client = self.__set_client__(
            provider.session, self.audit_config, provider.rate_limiter
        )

    @staticmethod
    def __set_client__(
        session: OktaSession, audit_config: dict, rate_limiter=None
    ) -> OktaSDKClient:
        # Start from the shared SDK config and layer the rate-limit settings on
        # top. `Client(config)` deep-merges these flat keys onto its defaults, so
        # `rateLimit`/`requestTimeout` override the SDK's built-in values.
        config = session.to_sdk_config()
        audit_config = audit_config or {}
        config["rateLimit"] = {
            "maxRetries": audit_config.get("okta_max_retries", DEFAULT_MAX_RETRIES)
        }
        config["requestTimeout"] = audit_config.get(
            "okta_request_timeout", DEFAULT_REQUEST_TIMEOUT
        )
        # Proactively pace outbound requests so scans stay under Okta's limits
        # instead of relying on the 429 retry as a safety net. The limiter is
        # shared across every service client of the provider, so the cap applies
        # to the aggregate request rate.
        if rate_limiter is not None:
            config["httpClient"] = build_throttled_http_client(rate_limiter)
        return OktaSDKClient(config)

    @staticmethod
    def _run(coro):
        """Run an okta-sdk-python coroutine from synchronous code."""
        return asyncio.run(coro)
