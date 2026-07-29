from unittest import mock

from prowler.providers.okta.services.apitoken.api_token_service import OktaApiToken
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_api_token_client(
    tokens: dict = None,
    known_network_zone_ids: set[str] = None,
    missing_scope: dict = None,
):
    client = mock.MagicMock()
    client.api_tokens = tokens or {}
    client.known_network_zone_ids = known_network_zone_ids or {"nzo-corp"}
    client.missing_scope = missing_scope or {
        "api_tokens": None,
        "network_zones": None,
        "user_roles": None,
        "user_groups": None,
    }
    client.provider = set_mocked_okta_provider()
    return client


def api_token(
    token_id: str = "00Tabcdefg1234567890",
    name: str = "CI token",
    *,
    user_id: str = "00uabcdefg1234567890",
    network_connection: str = "ZONE",
    network_includes: list[str] = None,
    network_excludes: list[str] = None,
    owner_roles: list[str] = None,
):
    return OktaApiToken(
        id=token_id,
        name=name,
        client_name="Okta API",
        user_id=user_id,
        network_connection=network_connection,
        network_includes=(
            network_includes if network_includes is not None else ["nzo-corp"]
        ),
        network_excludes=network_excludes or [],
        owner_roles=owner_roles or ["READ_ONLY_ADMIN"],
    )
