from unittest.mock import MagicMock

from prowler.providers.okta.models import OktaIdentityInfo, OktaSession

OKTA_ORG_DOMAIN = "acme.okta.com"
OKTA_CLIENT_ID = "0oa1234567890abcdef"
OKTA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----"


def set_mocked_okta_provider(
    session: OktaSession = None,
    identity: OktaIdentityInfo = None,
    audit_config: dict = None,
):
    if session is None:
        session = OktaSession(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            scopes=[
                "okta.policies.read",
                "okta.brands.read",
                "okta.apps.read",
                "okta.networkZones.read",
                "okta.apiTokens.read",
                "okta.roles.read",
                "okta.groups.read",
            ],
            private_key=OKTA_PRIVATE_KEY,
        )
    if identity is None:
        identity = OktaIdentityInfo(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            granted_scopes=[
                "okta.policies.read",
                "okta.brands.read",
                "okta.apps.read",
                "okta.networkZones.read",
                "okta.apiTokens.read",
                "okta.roles.read",
                "okta.groups.read",
            ],
        )

    provider = MagicMock()
    provider.type = "okta"
    provider.auth_method = "OAuth 2.0 (private-key JWT)"
    provider.session = session
    provider.identity = identity
    provider.audit_config = audit_config or {}
    return provider
