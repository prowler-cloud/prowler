import json
from types import SimpleNamespace
from unittest import mock

from pydantic import ValidationError

from prowler.providers.okta.models import OktaIdentityInfo
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


def _sdk_role_wrapped(role_type: str):
    """Mimic `ListGroupAssignedRoles200ResponseInner` — a oneOf wrapper
    holding the real StandardRole on `.actual_instance`. The Okta SDK
    actually returns this shape; treating it like the bare role yields
    `type=None, label=None` and the role silently vanishes from the
    check.
    """
    inner = _sdk_role(role_type)
    return SimpleNamespace(actual_instance=inner, type=None, label=None)


def _sdk_zone(zone_id: str, name: str):
    return SimpleNamespace(id=zone_id, name=name)


def _sdk_group(group_id: str):
    return SimpleNamespace(id=group_id)


async def _empty_list(*_a, **_k):
    return ([], _resp({}), None)


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
            mocked.list_user_groups = _empty_list
            mocked.list_group_assigned_roles = _empty_list
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
            mocked.list_user_groups = _empty_list
            mocked.list_group_assigned_roles = _empty_list
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
            mocked.list_user_groups = _empty_list
            mocked.list_group_assigned_roles = _empty_list
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

    def test_missing_api_token_scope_skips_dependent_api_calls(self):
        provider = set_mocked_okta_provider(
            identity=OktaIdentityInfo(
                org_domain="acme.okta.com",
                client_id="0oa1234567890abcdef",
                granted_scopes=["okta.networkZones.read", "okta.roles.read"],
            )
        )

        async def fail_if_called(*_a, **_k):
            raise AssertionError("API calls should not run without apiTokens scope")

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fail_if_called
            mocked.list_network_zones = fail_if_called
            mocked.list_assigned_roles_for_user = fail_if_called
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.missing_scope["api_tokens"] == "okta.apiTokens.read"
        assert service.api_tokens == {}
        assert service.known_network_zone_ids == set()

    def test_missing_network_zone_scope_skips_zone_api_call(self):
        provider = set_mocked_okta_provider(
            identity=OktaIdentityInfo(
                org_domain="acme.okta.com",
                client_id="0oa1234567890abcdef",
                granted_scopes=["okta.apiTokens.read", "okta.roles.read"],
            )
        )
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(*_a, **_k):
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fail_if_called(*_a, **_k):
            raise AssertionError("list_network_zones should not be called")

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_list_assigned_roles_for_user
            mocked.list_network_zones = fail_if_called
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.missing_scope["network_zones"] == "okta.networkZones.read"
        assert service.known_network_zone_ids == set()
        assert set(service.api_tokens.keys()) == {token.id}

    def test_missing_role_scope_skips_role_api_call(self):
        provider = set_mocked_okta_provider(
            identity=OktaIdentityInfo(
                org_domain="acme.okta.com",
                client_id="0oa1234567890abcdef",
                granted_scopes=["okta.apiTokens.read", "okta.networkZones.read"],
            )
        )
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fail_if_called(*_a, **_k):
            raise AssertionError("list_assigned_roles_for_user should not be called")

        async def fake_list_network_zones(*_a, **_k):
            return ([_sdk_zone("nzo-corp", "Corporate")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fail_if_called
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.missing_scope["user_roles"] == "okta.roles.read"
        assert service.api_tokens[token.id].owner_roles == []


class Test_ApiToken_service_group_inherited_roles:
    """Verifies effective-role resolution combines direct + group-inherited.

    Okta's `/api/v1/users/{userId}/roles` returns only directly-assigned
    admin roles. Roles inherited via group membership — the common path
    for Super Admin on trial tenants — are invisible to that endpoint.
    The service must enumerate the user's groups and combine each
    group's role assignments.
    """

    def test_group_inherited_super_admin_surfaces(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_direct_roles(*_a, **_k):
            return ([], _resp({}), None)

        async def fake_user_groups(user_id, *_a, **_k):
            assert user_id == token.user_id
            return (
                [_sdk_group("0gp-admins"), _sdk_group("0gp-eng")],
                _resp({}),
                None,
            )

        async def fake_group_roles(group_id, *_a, **_k):
            if group_id == "0gp-admins":
                return ([_sdk_role("SUPER_ADMIN")], _resp({}), None)
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fake_user_groups
            mocked.list_group_assigned_roles = fake_group_roles
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens[token.id].owner_roles == ["SUPER_ADMIN"]

    def test_direct_plus_group_roles_combined_and_deduped(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_direct_roles(*_a, **_k):
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fake_user_groups(*_a, **_k):
            return ([_sdk_group("0gp-1")], _resp({}), None)

        async def fake_group_roles(*_a, **_k):
            # READ_ONLY_ADMIN already comes from the direct path; the
            # dedupe should keep a single entry. SUPER_ADMIN is new.
            return (
                [_sdk_role("READ_ONLY_ADMIN"), _sdk_role("SUPER_ADMIN")],
                _resp({}),
                None,
            )

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fake_user_groups
            mocked.list_group_assigned_roles = fake_group_roles
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens[token.id].owner_roles == [
            "READ_ONLY_ADMIN",
            "SUPER_ADMIN",
        ]

    def test_role_resolution_cached_per_user_and_group(self):
        provider = set_mocked_okta_provider()
        token_a = _sdk_token(token_id="00Ttoken-a", user_id="00uowner-1")
        token_b = _sdk_token(token_id="00Ttoken-b", user_id="00uowner-1")
        token_c = _sdk_token(token_id="00Ttoken-c", user_id="00uowner-2")

        direct_calls: list[str] = []
        groups_calls: list[str] = []
        group_role_calls: list[str] = []

        async def fake_list_api_tokens(*_a, **_k):
            return ([token_a, token_b, token_c], _resp({}), None)

        async def fake_direct_roles(user_id, *_a, **_k):
            direct_calls.append(user_id)
            return ([], _resp({}), None)

        async def fake_user_groups(user_id, *_a, **_k):
            groups_calls.append(user_id)
            return ([_sdk_group("0gp-shared")], _resp({}), None)

        async def fake_group_roles(group_id, *_a, **_k):
            group_role_calls.append(group_id)
            return ([_sdk_role("HELP_DESK_ADMIN")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fake_user_groups
            mocked.list_group_assigned_roles = fake_group_roles
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        # Owner 00uowner-1 appears twice but is resolved once.
        assert sorted(direct_calls) == ["00uowner-1", "00uowner-2"]
        assert sorted(groups_calls) == ["00uowner-1", "00uowner-2"]
        # Shared group resolved once even though both owners belong to it.
        assert group_role_calls == ["0gp-shared"]
        for token in (token_a, token_b, token_c):
            assert service.api_tokens[token.id].owner_roles == ["HELP_DESK_ADMIN"]

    def test_missing_groups_scope_falls_back_to_direct_only(self):
        provider = set_mocked_okta_provider(
            identity=OktaIdentityInfo(
                org_domain="acme.okta.com",
                client_id="0oa1234567890abcdef",
                granted_scopes=[
                    "okta.apiTokens.read",
                    "okta.networkZones.read",
                    "okta.roles.read",
                ],
            )
        )
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_direct_roles(*_a, **_k):
            return ([_sdk_role("READ_ONLY_ADMIN")], _resp({}), None)

        async def fail_if_called(*_a, **_k):
            raise AssertionError(
                "list_user_groups must not be called without okta.groups.read"
            )

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fail_if_called
            mocked.list_group_assigned_roles = fail_if_called
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.missing_scope["user_groups"] == "okta.groups.read"
        assert service.api_tokens[token.id].owner_roles == ["READ_ONLY_ADMIN"]

    def test_wrapped_oneof_role_shape_is_unwrapped(self):
        """Regression: the SDK returns each role as a oneOf wrapper with
        the real StandardRole on `.actual_instance`. The previous
        `_role_to_string` read `.type`/`.label` from the wrapper, got
        None back, and produced an empty `owner_roles` — causing a
        Super Admin token to silently PASS the check."""
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_direct_roles(*_a, **_k):
            return ([_sdk_role_wrapped("SUPER_ADMIN")], _resp({}), None)

        async def fake_user_groups(*_a, **_k):
            return ([_sdk_group("0gp-extra")], _resp({}), None)

        async def fake_group_roles(*_a, **_k):
            return ([_sdk_role_wrapped("APP_ADMIN")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fake_user_groups
            mocked.list_group_assigned_roles = fake_group_roles
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens[token.id].owner_roles == [
            "SUPER_ADMIN",
            "APP_ADMIN",
        ]

    def test_group_role_fetch_failure_does_not_drop_other_groups(self):
        provider = set_mocked_okta_provider()
        token = _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([token], _resp({}), None)

        async def fake_direct_roles(*_a, **_k):
            return ([], _resp({}), None)

        async def fake_user_groups(*_a, **_k):
            return (
                [_sdk_group("0gp-broken"), _sdk_group("0gp-good")],
                _resp({}),
                None,
            )

        async def fake_group_roles(group_id, *_a, **_k):
            if group_id == "0gp-broken":
                raise RuntimeError("upstream parse failure")
            return ([_sdk_role("SUPER_ADMIN")], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_api_tokens = fake_list_api_tokens
            mocked.list_assigned_roles_for_user = fake_direct_roles
            mocked.list_user_groups = fake_user_groups
            mocked.list_group_assigned_roles = fake_group_roles
            mocked.list_network_zones = _empty_list
            mocked_client_cls.return_value = mocked
            service = ApiToken(provider)

        assert service.api_tokens[token.id].owner_roles == ["SUPER_ADMIN"]


class Test_ApiToken_service_sdk_validation_fallback:
    """Verifies the raw-JSON fallback for the Okta SDK Enhanced Dynamic
    Zone deserialization bug when listing zones for token validation.

    Without the fallback, `list_network_zones` raises ValidationError
    on tenants that have Enhanced Dynamic Zones with `asns.include: []`,
    `known_network_zone_ids` ends up empty, and every token that
    references a real zone fails as "unknown".
    """

    @staticmethod
    def _trigger_real_validation_error() -> ValidationError:
        try:
            from okta.models.enhanced_dynamic_network_zone_all_of_asns_include import (  # noqa: E501
                EnhancedDynamicNetworkZoneAllOfAsnsInclude,
            )

            EnhancedDynamicNetworkZoneAllOfAsnsInclude.from_dict([])
        except ValidationError as ve:
            return ve
        raise AssertionError("Expected pydantic ValidationError from Okta SDK model")

    def _build_service(self, raw_zones_payload, response=None, token=None):
        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()
        api_token = token or _sdk_token()

        async def fake_list_api_tokens(*_a, **_k):
            return ([api_token], _resp({}), None)

        async def fake_list_assigned_roles_for_user(*_a, **_k):
            return ([], _resp({}), None)

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **kwargs):
            return ({"url": kwargs.get("url", "")}, None)

        async def fake_raw_execute(_request):
            return (response, json.dumps(raw_zones_payload), None)

        sdk_mock = mock.MagicMock()
        sdk_mock.list_api_tokens = fake_list_api_tokens
        sdk_mock.list_assigned_roles_for_user = fake_list_assigned_roles_for_user
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            return ApiToken(provider)

    def test_raw_fallback_collects_zone_ids_and_names(self):
        zones_payload = [
            {"id": "nzo-corp", "name": "Corporate", "type": "IP"},
            {
                "id": "nzo-enhanced",
                "name": "DefaultEnhancedDynamicZone",
                "type": "DYNAMIC_V2",
                "asns": {"include": [], "exclude": []},
            },
        ]
        service = self._build_service(zones_payload)
        assert service.known_network_zone_ids == {
            "nzo-corp",
            "Corporate",
            "nzo-enhanced",
            "DefaultEnhancedDynamicZone",
        }

    def test_raw_fallback_handles_empty_payload(self):
        service = self._build_service([])
        assert service.known_network_zone_ids == set()

    def test_raw_fallback_handles_executor_error(self):
        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()

        async def fake_list_api_tokens(*_a, **_k):
            return ([], _resp({}), None)

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **_k):
            return (None, Exception("network down"))

        sdk_mock = mock.MagicMock()
        sdk_mock.list_api_tokens = fake_list_api_tokens
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = mock.AsyncMock()

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            service = ApiToken(provider)

        assert service.known_network_zone_ids == set()

    def test_raw_fallback_paginates_via_link_header(self):
        next_link = '<https://acme.okta.com/api/v1/zones?after=cursor-2>; rel="next"'
        page_1 = [{"id": "nzo-1", "name": "First"}]
        page_2 = [{"id": "nzo-2", "name": "Second"}]

        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()
        execute_calls = []

        async def fake_list_api_tokens(*_a, **_k):
            return ([], _resp({}), None)

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **kwargs):
            return ({"url": kwargs.get("url", "")}, None)

        async def fake_raw_execute(request):
            execute_calls.append(request)
            if len(execute_calls) == 1:
                return (
                    SimpleNamespace(headers={"link": next_link}),
                    json.dumps(page_1),
                    None,
                )
            return (SimpleNamespace(headers={}), json.dumps(page_2), None)

        sdk_mock = mock.MagicMock()
        sdk_mock.list_api_tokens = fake_list_api_tokens
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            service = ApiToken(provider)

        assert len(execute_calls) == 2
        assert "after=cursor-2" in execute_calls[1]["url"]
        assert service.known_network_zone_ids == {
            "nzo-1",
            "First",
            "nzo-2",
            "Second",
        }
