from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
    SignInPage,
    Signon,
    _next_after_cursor,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _fake_policy(
    policy_id: str,
    name: str,
    system: bool = True,
    priority: int | None = 1,
    status: str = "ACTIVE",
):
    p = mock.MagicMock()
    p.id = policy_id
    p.name = name
    p.priority = priority
    p.status = status
    p.system = system
    return p


def _fake_rule(
    rule_id: str,
    name: str,
    *,
    system: bool = False,
    priority: int | None = 1,
    status: str = "ACTIVE",
    max_session_idle_minutes: int = None,
):
    r = mock.MagicMock()
    r.id = rule_id
    r.name = name
    r.priority = priority
    r.status = status
    r.system = system
    r.actions.signon.session.max_session_idle_minutes = max_session_idle_minutes
    r.actions.signon.session.max_session_lifetime_minutes = None
    r.actions.signon.session.use_persistent_cookie = None
    r.conditions.network.include = []
    r.conditions.network.exclude = []
    return r


def _fake_brand(brand_id: str, name: str):
    b = mock.MagicMock()
    b.id = brand_id
    b.name = name
    return b


def _fake_sign_in_page(page_content: str):
    p = mock.MagicMock()
    p.page_content = page_content
    return p


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


async def _empty_brands(*_a, **_k):
    return ([], _resp({}), None)


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
            mocked.list_brands = _empty_brands
            mocked_client_cls.return_value = mocked

            service = Signon(provider)

        assert "pol-default" in service.global_session_policies
        policy_obj = service.global_session_policies["pol-default"]
        assert isinstance(policy_obj, GlobalSessionPolicy)
        assert policy_obj.is_default is True
        assert policy_obj.priority == 1
        assert policy_obj.status == "ACTIVE"
        assert len(policy_obj.rules) == 2
        rules_by_name = {r.name: r for r in policy_obj.rules}
        assert isinstance(rules_by_name["Default Rule"], GlobalSessionPolicyRule)
        assert rules_by_name["Default Rule"].is_default is True
        assert rules_by_name["Default Rule"].priority == 1
        assert rules_by_name["Default Rule"].status == "ACTIVE"
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
            mocked.list_brands = _empty_brands
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
            mocked.list_brands = _empty_brands
            mocked_client_cls.return_value = mocked
            service = Signon(provider)

        assert service.global_session_policies == {}


class Test_Signon_service_brands:
    """Brand sign-in page fetching for the DOD banner check."""

    def _build_with_brands(
        self,
        provider,
        brands_response,
        sign_in_page_responses: dict,
        default_sign_in_page_responses: dict | None = None,
    ):
        async def fake_list_policies(*_a, **_k):
            return ([], _resp({}), None)

        async def fake_list_brands(*_a, **_k):
            return brands_response

        async def fake_get_sign_in_page(brand_id, *_a, **_k):
            return sign_in_page_responses[brand_id]

        async def fake_get_default_sign_in_page(brand_id, *_a, **_k):
            return default_sign_in_page_responses[brand_id]

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_brands = fake_list_brands
            mocked.get_customized_sign_in_page = fake_get_sign_in_page
            mocked.get_default_sign_in_page = fake_get_default_sign_in_page
            mocked_client_cls.return_value = mocked
            return Signon(provider)

    def test_fetches_brand_with_customized_page(self):
        provider = set_mocked_okta_provider()
        brand = _fake_brand("brand-1", "Primary")
        page = _fake_sign_in_page("<html>banner here</html>")
        service = self._build_with_brands(
            provider,
            brands_response=([brand], _resp({}), None),
            sign_in_page_responses={"brand-1": (page, _resp({}), None)},
        )

        assert "brand-1" in service.sign_in_pages
        result = service.sign_in_pages["brand-1"]
        assert isinstance(result, SignInPage)
        assert result.is_customized is True
        assert result.page_content == "<html>banner here</html>"
        assert result.fetch_error is None

    def test_404_falls_back_to_default_sign_in_page(self):
        provider = set_mocked_okta_provider()
        brand = _fake_brand("brand-1", "Primary")
        default_page = _fake_sign_in_page("<html>default banner here</html>")
        service = self._build_with_brands(
            provider,
            brands_response=([brand], _resp({}), None),
            sign_in_page_responses={
                "brand-1": (None, _resp({}), Exception("404 Not Found"))
            },
            default_sign_in_page_responses={"brand-1": (default_page, _resp({}), None)},
        )

        assert service.sign_in_pages["brand-1"].is_customized is False
        assert service.sign_in_pages["brand-1"].fetch_error is None
        assert (
            service.sign_in_pages["brand-1"].page_content
            == "<html>default banner here</html>"
        )

    def test_default_sign_in_page_error_captured_when_customized_page_missing(self):
        provider = set_mocked_okta_provider()
        brand = _fake_brand("brand-1", "Primary")
        service = self._build_with_brands(
            provider,
            brands_response=([brand], _resp({}), None),
            sign_in_page_responses={
                "brand-1": (None, _resp({}), Exception("404 Not Found"))
            },
            default_sign_in_page_responses={
                "brand-1": (None, _resp({}), Exception("403 Forbidden"))
            },
        )

        result = service.sign_in_pages["brand-1"]
        assert result.is_customized is False
        assert "403" in result.fetch_error

    def test_403_captured_into_fetch_error(self):
        provider = set_mocked_okta_provider()
        brand = _fake_brand("brand-1", "Primary")
        service = self._build_with_brands(
            provider,
            brands_response=([brand], _resp({}), None),
            sign_in_page_responses={
                "brand-1": (None, _resp({}), Exception("403 Forbidden: invalid_scope"))
            },
            default_sign_in_page_responses={},
        )

        result = service.sign_in_pages["brand-1"]
        assert result.is_customized is False
        assert "403" in result.fetch_error

    def test_returns_empty_on_brands_api_error(self):
        provider = set_mocked_okta_provider()

        async def fake_list_policies(*_a, **_k):
            return ([], _resp({}), None)

        async def failing_brands(*_a, **_k):
            return ([], _resp({}), Exception("Brands API unavailable"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_policies = fake_list_policies
            mocked.list_brands = failing_brands
            mocked_client_cls.return_value = mocked
            service = Signon(provider)

        assert service.sign_in_pages == {}

    def test_handles_multiple_brands(self):
        provider = set_mocked_okta_provider()
        brand_a = _fake_brand("brand-a", "Brand A")
        brand_b = _fake_brand("brand-b", "Brand B")
        page_a = _fake_sign_in_page("<html>A</html>")

        service = self._build_with_brands(
            provider,
            brands_response=([brand_a, brand_b], _resp({}), None),
            sign_in_page_responses={
                "brand-a": (page_a, _resp({}), None),
                "brand-b": (None, _resp({}), Exception("404 not found")),
            },
            default_sign_in_page_responses={
                "brand-b": (
                    _fake_sign_in_page("<html>default B</html>"),
                    _resp({}),
                    None,
                )
            },
        )

        assert set(service.sign_in_pages.keys()) == {"brand-a", "brand-b"}
        assert service.sign_in_pages["brand-a"].page_content == "<html>A</html>"
        assert service.sign_in_pages["brand-b"].is_customized is False
        assert service.sign_in_pages["brand-b"].page_content == "<html>default B</html>"
