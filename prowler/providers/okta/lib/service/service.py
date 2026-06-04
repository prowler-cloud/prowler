import asyncio
from typing import TYPE_CHECKING

from okta.client import Client as OktaSDKClient

from prowler.providers.okta.models import OktaSession

if TYPE_CHECKING:
    from prowler.providers.okta.okta_provider import OktaProvider


class OktaService:
    """Base class for Okta service implementations.

    Wraps the async okta-sdk-python `Client` so that subclasses can stay
    synchronous like the other Prowler providers. The SDK auto-refreshes
    the OAuth access token; nothing to manage here.
    """

    def __init__(self, service: str, provider: "OktaProvider"):
        self.provider = provider
        self.service = service
        self.client = self.__set_client__(provider.session)
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    @staticmethod
    def __set_client__(session: OktaSession) -> OktaSDKClient:
        return OktaSDKClient(session.to_sdk_config())

    @staticmethod
    def _run(coro):
        """Run an okta-sdk-python coroutine from synchronous code."""
        return asyncio.run(coro)

    def _missing_scopes(self, required_scopes: list[str]) -> list[str]:
        """Return required OAuth scopes not granted to the Okta service app."""
        granted_scopes = set(getattr(self.provider.session, "scopes", []) or [])
        return [scope for scope in required_scopes if scope not in granted_scopes]
