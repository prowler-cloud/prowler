from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate
from prowler.providers.okta.lib.service.service import OktaService

# Okta's API value for the "Smart Card" IdP shown in the Admin Console.
# The UI label is "Smart Card IdP" but the `type` field on the API response
# is `X509` (Mutual TLS) — that is the value we filter on.
SMART_CARD_IDP_TYPE = "X509"

REQUIRED_SCOPES: dict[str, str] = {
    "identity_providers": "okta.idps.read",
}


class Idp(OktaService):
    """Fetches Okta Identity Providers.

    Populates `self.identity_providers` keyed by IdP id. Each entry
    captures the minimum fields the bundled checks read: identity
    (`id`, `name`), `type`, `status`, and — for `X509` Smart Card IdPs
    — the certificate-chain `issuer` and `kid` exposed by Okta's
    `protocol.credentials.trust` structure. Reading the issuer DN lets
    the check surface it for out-of-band verification against the
    DOD-approved CA list.

    Required OAuth scopes (`REQUIRED_SCOPES`) are compared against the
    access token's granted scopes (`provider.identity.granted_scopes`).
    Missing scopes are recorded in `self.missing_scope` so the check
    can emit an explicit MANUAL finding.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }

        self.identity_providers: dict[str, OktaIdentityProvider] = (
            {}
            if self.missing_scope["identity_providers"]
            else self._list_identity_providers()
        )

    def _list_identity_providers(self) -> dict:
        logger.info("Idp - Listing Okta Identity Providers...")
        try:
            return self._run(self._fetch_identity_providers())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_identity_providers(self) -> dict:
        result: dict[str, OktaIdentityProvider] = {}
        all_idps, err = await paginate(
            lambda after: self.client.list_identity_providers(after=after)
        )
        if err is not None:
            logger.error(f"Error listing identity providers: {err}")
            return result

        for idp in all_idps:
            idp_id = getattr(idp, "id", "") or ""
            if not idp_id:
                continue
            issuer, kid = _trust_fields(idp)
            result[idp_id] = OktaIdentityProvider(
                id=idp_id,
                name=getattr(idp, "name", "") or "",
                type=_stringify_enum(getattr(idp, "type", None)) or "",
                status=_stringify_enum(getattr(idp, "status", None)) or "",
                trust_issuer=issuer,
                trust_kid=kid,
            )
        return result


def _trust_fields(idp) -> tuple[Optional[str], Optional[str]]:
    """Extract `issuer` and `kid` from an `X509` IdP's protocol.credentials.trust.

    The SDK exposes `IdentityProvider.protocol` as `IdentityProviderProtocol`,
    a Pydantic v2 oneOf wrapper that holds the concrete protocol (ProtocolMtls
    for X509 IdPs) on `actual_instance`. `credentials` is not proxied on the
    wrapper, so reading it directly returns None — we have to unwrap first.
    """
    protocol = getattr(idp, "protocol", None)
    if protocol is None:
        return None, None
    actual_protocol = getattr(protocol, "actual_instance", None) or protocol
    credentials = getattr(actual_protocol, "credentials", None)
    if credentials is None:
        return None, None
    trust = getattr(credentials, "trust", None)
    if trust is None:
        return None, None
    return getattr(trust, "issuer", None), getattr(trust, "kid", None)


def _stringify_enum(value) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "value", None) or str(value)


class OktaIdentityProvider(BaseModel):
    id: str
    name: str = ""
    type: str = ""
    status: str = ""
    trust_issuer: Optional[str] = None
    trust_kid: Optional[str] = None
