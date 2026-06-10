import json
from unittest import mock

from okta.models.identity_provider_protocol import IdentityProviderProtocol

from prowler.providers.okta.services.idp.idp_service import Idp, OktaIdentityProvider
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


def _fake_idp(idp_id, name, type_, status="ACTIVE", issuer=None, kid=None):
    # Build a real `IdentityProviderProtocol` when issuer/kid are provided
    # so the test exercises the SDK's Pydantic v2 oneOf wrapper — credentials
    # live on `actual_instance`, not directly on the wrapper. MagicMock
    # auto-attribute-creation would otherwise hide a missed unwrap.
    idp = mock.MagicMock()
    idp.id = idp_id
    idp.name = name
    idp.type = type_
    idp.status = status
    if issuer is None and kid is None:
        idp.protocol = None
    else:
        idp.protocol = IdentityProviderProtocol.from_json(
            json.dumps(
                {
                    "type": "MTLS",
                    "credentials": {"trust": {"issuer": issuer, "kid": kid}},
                }
            )
        )
    return idp


def _patch_sdk(**methods):
    return mock.patch(
        "prowler.providers.okta.lib.service.service.OktaSDKClient",
        return_value=mock.MagicMock(**methods),
    )


class Test_Idp_service:
    def test_fetches_idps_with_trust_fields(self):
        provider = set_mocked_okta_provider()
        x509 = _fake_idp(
            "0oa1",
            "CAC",
            "X509",
            issuer="CN=DOD ROOT CA 6",
            kid="kid-1",
        )
        saml = _fake_idp("0oa2", "Corp", "SAML2")

        async def fake_list(*_a, **_k):
            return ([x509, saml], _resp({}), None)

        with _patch_sdk(list_identity_providers=fake_list):
            service = Idp(provider)

        assert set(service.identity_providers.keys()) == {"0oa1", "0oa2"}
        assert isinstance(service.identity_providers["0oa1"], OktaIdentityProvider)
        assert service.identity_providers["0oa1"].trust_issuer == "CN=DOD ROOT CA 6"
        assert service.identity_providers["0oa1"].trust_kid == "kid-1"
        assert service.identity_providers["0oa2"].trust_issuer is None

    def test_returns_empty_on_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("API failure"))

        with _patch_sdk(list_identity_providers=failing):
            service = Idp(provider)

        assert service.identity_providers == {}
