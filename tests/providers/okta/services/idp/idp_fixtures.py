"""Shared helpers for `idp` service check tests."""

from unittest import mock

from prowler.providers.okta.services.idp.idp_service import OktaIdentityProvider
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_idp_client(
    identity_providers: dict = None,
    missing_scope: dict = None,
):
    client = mock.MagicMock()
    client.identity_providers = identity_providers or {}
    client.provider = set_mocked_okta_provider()
    client.audit_config = {}
    client.missing_scope = missing_scope or {"identity_providers": None}
    return client


def smart_card_idp(
    idp_id: str = "0oa-x509",
    name: str = "CAC IdP",
    status: str = "ACTIVE",
    issuer: str = "CN=DOD ROOT CA 6",
    kid: str = "kid-abc-123",
):
    return OktaIdentityProvider(
        id=idp_id,
        name=name,
        type="X509",
        status=status,
        trust_issuer=issuer,
        trust_kid=kid,
    )


def non_smart_card_idp(
    idp_id: str = "0oa-saml",
    name: str = "Corporate SAML",
    type: str = "SAML2",
    status: str = "ACTIVE",
):
    return OktaIdentityProvider(id=idp_id, name=name, type=type, status=status)
