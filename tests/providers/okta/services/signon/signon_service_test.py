from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
    Signon,
    _next_after_cursor,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _fake_policy(policy_id: str, name: str, system: bool = True):
    p = mock.MagicMock()
    p.id = policy_id
    p.name = name
    p.status = "ACTIVE"
    p.system = system
    return p


def _fake_rule(
    rule_id: str,
    name: str,
    *,
    system: bool = False,
    max_session_idle_minutes: int = None,
):
    r = mock.MagicMock()
    r.id = rule_id
    r.name = name
    r.system = system
    r.actions.signon.session.max_session_idle_minutes = max_session_idle_minutes
    r.actions.signon.session.max_session_lifetime_minutes = None
    r.actions.signon.session.use_persistent_cookie = None
    r.conditions.network.include = []
    r.conditions.network.exclude = []
    return r


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


class Test_next_after_cursor:
    def test_no_resp_returns_none(self):
        assert _next_after_cursor(None) is None

    def test_no_link_header_returns_none(self):
        assert _next_after_cursor(_resp({})) is None

    def test_extracts_after_param(self):
        link = (
            '<https://acme.okta.com/api/v1/policies?limit=20>; rel="self", '
            '<https://acme.okta.com/api/v1/policies?after=abc123&limit=20>; rel="next"'
        )
        assert _next_after_cursor(_resp({"link": link})) == "abc123"

    def test_link_without_next_returns_none(self):
        link = '<https://acme.okta.com/api/v1/policies?limit=20>; rel="self"'
        assert _next_after_cursor(_resp({"link": link})) is None


class Test_Signon_service:
    def test_fetches_policies_and_rules(self):
        provider = set_mocked_okta_provider()

        policy = _fake_policy("pol-default", "Default Policy", system=True)
        rule_default = _fake_rule(
            "rule-default", "Default Rule", system=True, max_session_idle_minutes=480
        )
        rule_compliant = _fake_rule(
            "rule-15", "Strict 15min", system=False, max_session_idle_minutes=15
        )

        async def fake_list_policies(*_a, **_k):
            return ([policy], _resp({}), None)

        async def fake_list_rules(*_a, **_k):
            return ([rule_default, rule_compliant], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_policy_rules = fake_list_rules
            mocked_client_cls.return_value = mocked

            service = Signon(provider)

        assert "pol-default" in service.global_session_policies
        policy_obj = service.global_session_policies["pol-default"]
        assert isinstance(policy_obj, GlobalSessionPolicy)
        assert policy_obj.is_default is True
        assert len(policy_obj.rules) == 2
        rules_by_name = {r.name: r for r in policy_obj.rules}
        assert isinstance(rules_by_name["Default Rule"], GlobalSessionPolicyRule)
        assert rules_by_name["Default Rule"].is_default is True
        assert rules_by_name["Strict 15min"].is_default is False
        assert rules_by_name["Strict 15min"].max_session_idle_minutes == 15

    def test_paginates_via_link_header(self):
        provider = set_mocked_okta_provider()

        page1_policy = _fake_policy("pol-1", "Default Policy")
        page2_policy = _fake_policy("pol-2", "Custom Policy", system=False)
        next_link = '<https://acme.okta.com/api/v1/policies?after=cursor-2>; rel="next"'

        calls = []

        async def fake_list_policies(*_a, **kwargs):
            calls.append(kwargs.get("after"))
            if kwargs.get("after") is None:
                return ([page1_policy], _resp({"link": next_link}), None)
            return ([page2_policy], _resp({}), None)

        async def fake_list_rules(*_a, **_k):
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_policy_rules = fake_list_rules
            mocked_client_cls.return_value = mocked
            service = Signon(provider)

        assert calls == [None, "cursor-2"]
        assert set(service.global_session_policies.keys()) == {"pol-1", "pol-2"}

    def test_returns_empty_on_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("E0000007: not found"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = failing
            mocked_client_cls.return_value = mocked
            service = Signon(provider)

        assert service.global_session_policies == {}

    def test_passes_kid_to_sdk_client_when_set(self):
        from prowler.providers.okta.models import OktaSession

        provider = set_mocked_okta_provider(
            session=OktaSession(
                org_url="https://acme.okta.com",
                client_id="cid",
                scopes=["okta.policies.read"],
                private_key="-----BEGIN-----",
                kid="kid-123",
            )
        )

        async def empty(*_a, **_k):
            return ([], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = empty
            mocked_client_cls.return_value = mocked
            Signon(provider)

        config_arg = mocked_client_cls.call_args.args[0]
        assert config_arg["kid"] == "kid-123"
