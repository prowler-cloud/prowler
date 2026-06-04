from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.okta.okta_provider import DEFAULT_SCOPES
from prowler.providers.okta.services.apitoken.api_token_service import (
    API_TOKENS_READ_SCOPE,
    NETWORK_ZONES_READ_SCOPE,
    ROLES_READ_SCOPE,
    ApiToken,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _resp(headers: dict = None):
    return SimpleNamespace(headers=headers or {})


def _sdk_token(
    token_id: str = "00Tabcdefg1234567890",
    name: str = "CI token",
    *,
    user_id: str = "00uabcdefg1234567890",
    connection: str = "ZONE",
    include: list[str] = None,
    exclude: list[str] = None,
):
    return SimpleNamespace(
        id=token_id,
        name=name,
        client_name="Okta API",
        user_id=user_id,
        network=SimpleNamespace(
            connection=connection,
            include=include if include is not None else ["nzo-corp"],
            exclude=exclude or [],
        ),
    )


def _sdk_role(role_type: str):
    return SimpleNamespace(type=role_type, label=role_type.replace("_", " ").title())


def _sdk_zone(zone_id: str, name: str):
    return SimpleNamespace(id=zone_id, name=name)


class Test_ApiToken_service:
    def test_fetches_tokens_roles_and_known_network_zones(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens():
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(user_id):
            assert user_id == token.user_id
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_list_network_zones(after=None, limit=None):
            assert after is None
            assert limit == 200
            return ([_sdk_zone("nzo-corp", "Corporate")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_list_assigned_roles_for_user
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked

            service = ApiToken(provider)

        assert set(service.api_tokens.keys()) == {token.id}
        assert service.api_tokens[token.id].network_connection == "ZONE"
        assert service.api_tokens[token.id].owner_roles == ["READ_ONLY_ADMIN"]
        assert service.known_network_zone_ids == {"nzo-corp", "Corporate"}

    def test_role_fetch_error_keeps_token_with_empty_roles(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens():
            return ([token], _resp({}), None)

        async def fake_roles_error(user_id):
            assert user_id == token.user_id
            return ([], _resp({}), Exception("forbidden"))

        async def fake_list_network_zones(after=None, limit=None):
            assert after is None
            assert limit == 200
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_roles_error
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens[token.id].owner_roles == []

    def test_paginates_known_network_zones_for_token_validation(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token(include=["nzo-page-2"])
        next_link = '<https://acme.okta.com/api/v1/zones?after=cursor-2>; rel="next"'

        async def fake_list_api_tokens():
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(user_id):
            assert user_id == token.user_id
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_list_network_zones(after=None, limit=None):
            assert limit == 200
            if after is None:
                return (
                    [_sdk_zone("nzo-page-1", "First")],
                    _resp({"link": next_link}),
                    None,
                )
            return ([_sdk_zone("nzo-page-2", "Second")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_list_assigned_roles_for_user
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.known_network_zone_ids == {
            "nzo-page-1",
            "First",
            "nzo-page-2",
            "Second",
        }

    def test_returns_empty_on_token_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing():
            return ([], _resp({}), Exception("forbidden"))

        async def fake_list_network_zones(after=None, limit=None):
            assert after is None
            assert limit == 200
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = failing
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens == {}

    @pytest.mark.parametrize(
        "missing_scope, expected_calls, expected_tokens, expected_zones, expected_roles",
        [
            (
                API_TOKENS_READ_SCOPE,
                [],
                set(),
                set(),
                None,
            ),
            (
                NETWORK_ZONES_READ_SCOPE,
                ["list_api_tokens", "list_assigned_roles_for_user"],
                {"00Tabcdefg1234567890"},
                set(),
                ["READ_ONLY_ADMIN"],
            ),
            (
                ROLES_READ_SCOPE,
                ["list_network_zones", "list_api_tokens"],
                {"00Tabcdefg1234567890"},
                {"nzo-corp", "Corporate"},
                [],
            ),
        ],
    )
    def test_missing_scope_skips_corresponding_sdk_call(
        self,
        missing_scope,
        expected_calls,
        expected_tokens,
        expected_zones,
        expected_roles,
    ):
        provider = set_mocked_okta_provider(
            scopes=[scope for scope in DEFAULT_SCOPES if scope != missing_scope]
        )
        token = _sdk_token()
        calls = []

        async def fake_list_api_tokens():
            if missing_scope == API_TOKENS_READ_SCOPE:
                raise AssertionError("list_api_tokens must not be called")
            calls.append("list_api_tokens")
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(user_id):
            if missing_scope == ROLES_READ_SCOPE:
                raise AssertionError("list_assigned_roles_for_user must not be called")
            assert user_id == token.user_id
            calls.append("list_assigned_roles_for_user")
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_list_network_zones(after=None, limit=None):
            if missing_scope in {API_TOKENS_READ_SCOPE, NETWORK_ZONES_READ_SCOPE}:
                raise AssertionError("list_network_zones must not be called")
            assert after is None
            assert limit == 200
            calls.append("list_network_zones")
            return ([_sdk_zone("nzo-corp", "Corporate")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_list_assigned_roles_for_user
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.missing_scopes == [missing_scope]
        assert set(service.api_tokens.keys()) == expected_tokens
        assert service.known_network_zone_ids == expected_zones
        if expected_roles is not None:
            assert service.api_tokens[token.id].owner_roles == expected_roles
        assert calls == expected_calls
