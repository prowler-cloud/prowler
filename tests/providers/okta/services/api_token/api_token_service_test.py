from types import SimpleNamespace
from unittest import mock

from prowler.providers.okta.services.apitoken.api_token_service import ApiToken
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

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(user_id, *_a, **_k):
            assert user_id == token.user_id
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_list_network_zones(*_a, **_k):
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

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_roles_error(*_a, **_k):
            return ([], _resp({}), Exception("forbidden"))

        async def fake_list_network_zones(*_a, **_k):
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

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(*_a, **_k):
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_list_network_zones(*_a, **kwargs):
            if kwargs.get("after") is None:
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

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("forbidden"))

        async def fake_list_network_zones(*_a, **_k):
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
