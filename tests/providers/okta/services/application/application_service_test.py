import json
from unittest import mock

from prowler.providers.okta.models import OktaIdentityInfo
from prowler.providers.okta.services.application.application_service import (
    Application,
    AuthenticationPolicy,
    OktaBuiltInApp,
    _policy_id_from_href,
)
from tests.providers.okta.okta_fixtures import (
    OKTA_CLIENT_ID,
    OKTA_ORG_DOMAIN,
    set_mocked_okta_provider,
)


def _resp(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


def _fake_app(
    app_id: str,
    name: str,
    *,
    access_policy_href: str = None,
    label: str = "",
    status: str = "ACTIVE",
):
    a = mock.MagicMock()
    a.id = app_id
    a.name = name
    a.label = label
    a.status = status
    if access_policy_href is None:
        a.links = None
    else:
        a.links.access_policy.href = access_policy_href
    return a


def _fake_rule(
    *,
    rule_id: str = "rule-1",
    name: str = "Catch-all Rule",
    priority: int = 1,
    status: str = "ACTIVE",
    system: bool = False,
    factor_mode: str = None,
    phishing_resistant: str = None,
    access: str = "ALLOW",
    network_connection: str = None,
    network_include: list[str] = None,
    network_exclude: list[str] = None,
):
    r = mock.MagicMock()
    r.id = rule_id
    r.name = name
    r.priority = priority
    r.status = status
    r.system = system
    r.actions.app_sign_on.verification_method.factor_mode = factor_mode
    r.actions.app_sign_on.verification_method.type = "ASSURANCE"
    r.actions.app_sign_on.access = access
    r.conditions.network.connection = network_connection
    r.conditions.network.include = network_include or []
    r.conditions.network.exclude = network_exclude or []
    if phishing_resistant is None:
        r.actions.app_sign_on.verification_method.constraints = []
    else:
        constraint = mock.MagicMock()
        constraint.possession.phishing_resistant = phishing_resistant
        r.actions.app_sign_on.verification_method.constraints = [constraint]
    return r


def _fake_admin_console_settings(idle: int = 15, lifetime: int = 720):
    s = mock.MagicMock()
    s.session_idle_timeout_minutes = idle
    s.session_max_lifetime_minutes = lifetime
    return s


class Test_policy_id_from_href:
    def test_returns_trailing_segment(self):
        href = "https://acme.okta.com/api/v1/policies/rst123"
        assert _policy_id_from_href(href) == "rst123"

    def test_strips_trailing_slash(self):
        assert (
            _policy_id_from_href("https://acme.okta.com/api/v1/policies/rst123/")
            == "rst123"
        )

    def test_handles_relative_path(self):
        assert _policy_id_from_href("/api/v1/policies/rst-abc") == "rst-abc"

    def test_none_returns_none(self):
        assert _policy_id_from_href(None) is None

    def test_empty_returns_none(self):
        assert _policy_id_from_href("") is None


def _patch_sdk(**methods):
    """Returns a context manager that patches OktaSDKClient with the given async methods."""
    return mock.patch(
        "prowler.providers.okta.lib.service.service.OktaSDKClient",
        return_value=mock.MagicMock(**methods),
    )


class Test_Application_service:
    def test_fetches_admin_console_settings_and_built_in_apps(self):
        provider = set_mocked_okta_provider()

        admin_console_app = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rstadminconsole",
            label="Okta Admin Console",
        )
        dashboard_app = _fake_app(
            "0oadashboard",
            "okta_enduser",
            access_policy_href="https://acme.okta.com/api/v1/policies/rstdashboard",
            label="Okta Dashboard",
        )

        async def fake_get_first_party(_app_name):
            return (
                _fake_admin_console_settings(idle=15, lifetime=720),
                _resp({}),
                None,
            )

        async def fake_list_applications(*_a, **kwargs):
            name_filter = kwargs.get("filter", "")
            if "saasure" in name_filter:
                return ([admin_console_app], _resp({}), None)
            if "okta_enduser" in name_filter:
                return ([dashboard_app], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_list_policy_rules(_policy_id, **_k):
            rule = _fake_rule(name="Top", priority=1, factor_mode="2FA")
            return ([rule], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_get_first_party,
            list_applications=fake_list_applications,
            list_policy_rules=fake_list_policy_rules,
        ):
            service = Application(provider)

        assert service.admin_console_app_settings.session_idle_timeout_minutes == 15
        assert service.admin_console_app_settings.session_max_lifetime_minutes == 720
        assert set(service.built_in_apps.keys()) == {"saasure", "okta_enduser"}
        admin = service.built_in_apps["saasure"]
        assert isinstance(admin, OktaBuiltInApp)
        assert admin.access_policy_id == "rstadminconsole"
        assert isinstance(admin.access_policy, AuthenticationPolicy)
        assert admin.access_policy.rules[0].factor_mode == "2FA"

    def test_missing_admin_console_settings_endpoint_returns_none(self):
        provider = set_mocked_okta_provider()

        async def failing_settings(_app_name):
            return (None, _resp({}), Exception("404 Not Found"))

        async def fake_list_applications(*_a, **_k):
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=failing_settings,
            list_applications=fake_list_applications,
            list_policy_rules=mock.AsyncMock(),
        ):
            service = Application(provider)

        assert service.admin_console_app_settings is None
        assert service.built_in_apps == {}

    def test_built_in_app_without_access_policy_link(self):
        provider = set_mocked_okta_provider()
        admin_console_app = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href=None,
            label="Okta Admin Console",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_list_applications(*_a, **kwargs):
            if "saasure" in kwargs.get("filter", ""):
                return ([admin_console_app], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_list_policy_rules(*_a, **_k):
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_list_applications,
            list_policy_rules=fake_list_policy_rules,
        ):
            service = Application(provider)

        admin = service.built_in_apps["saasure"]
        assert admin.access_policy_id is None
        assert admin.access_policy is None

    def test_paginates_list_applications_via_link_header(self):
        provider = set_mocked_okta_provider()
        page1 = _fake_app("0oa-page-1", "saasure")
        page2 = _fake_app(
            "0oa-page-2",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst1",
        )
        next_link = '<https://acme.okta.com/api/v1/apps?after=cursor-2>; rel="next"'

        calls = []

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_list_applications(*_a, **kwargs):
            name_filter = kwargs.get("filter", "")
            if "saasure" in name_filter:
                if kwargs.get("after") is None:
                    calls.append("page1")
                    return ([page1], _resp({"link": next_link}), None)
                calls.append("page2")
                return ([page2], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_list_policy_rules(*_a, **_k):
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_list_applications,
            list_policy_rules=fake_list_policy_rules,
        ):
            service = Application(provider)

        assert calls == ["page1", "page2"]
        # Pagination returns both, but we only keep the first match per
        # canonical name. Make sure that path doesn't break.
        assert "saasure" in service.built_in_apps

    def test_returns_empty_on_apps_api_error(self):
        provider = set_mocked_okta_provider()

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def failing_apps(*_a, **_k):
            return ([], _resp({}), Exception("E0000007: scope not found"))

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=failing_apps,
            list_policy_rules=mock.AsyncMock(),
        ):
            service = Application(provider)

        assert service.built_in_apps == {}

    def test_skips_fetch_when_apps_scope_missing(self):
        identity = OktaIdentityInfo(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            granted_scopes=["okta.policies.read"],
        )
        provider = set_mocked_okta_provider(identity=identity)

        list_apps_called = False
        get_settings_called = False

        async def fake_settings(_app_name):
            nonlocal get_settings_called
            get_settings_called = True
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **_k):
            nonlocal list_apps_called
            list_apps_called = True
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=mock.AsyncMock(),
        ):
            service = Application(provider)

        assert list_apps_called is False
        assert get_settings_called is False
        assert service.built_in_apps == {}
        assert service.admin_console_app_settings is None
        assert service.missing_scope["admin_console_app_settings"] == "okta.apps.read"
        assert service.missing_scope["built_in_apps"] == "okta.apps.read"
        assert service.missing_scope["integrated_apps"] == "okta.apps.read"
        assert service.missing_scope["access_policies"] is None

    def test_skips_policy_fetch_when_policies_scope_missing(self):
        identity = OktaIdentityInfo(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            granted_scopes=["okta.apps.read"],
        )
        provider = set_mocked_okta_provider(identity=identity)

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **_k):
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=mock.AsyncMock(),
        ):
            service = Application(provider)

        # When only one scope is missing, we still expose
        # admin_console_app_settings (uses okta.apps.read which IS granted)
        # but skip the joint built_in_apps+policies path.
        assert service.admin_console_app_settings is not None
        assert service.built_in_apps == {}
        assert service.missing_scope["admin_console_app_settings"] is None
        assert service.missing_scope["built_in_apps"] is None
        assert service.missing_scope["integrated_apps"] is None
        assert service.missing_scope["access_policies"] == "okta.policies.read"

    def test_unknown_granted_scopes_falls_back_to_attempting_fetch(self):
        identity = OktaIdentityInfo(
            org_domain=OKTA_ORG_DOMAIN,
            client_id=OKTA_CLIENT_ID,
            granted_scopes=[],
        )
        provider = set_mocked_okta_provider(identity=identity)

        called = {"settings": False, "apps": False}

        async def fake_settings(_app_name):
            called["settings"] = True
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **_k):
            called["apps"] = True
            return ([], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=mock.AsyncMock(),
        ):
            Application(provider)

        assert called["settings"] is True
        assert called["apps"] is True

    def test_phishing_resistant_constraint_picked_up_from_rule(self):
        provider = set_mocked_okta_provider()
        app = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-pr",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            if "saasure" in kwargs.get("filter", ""):
                return ([app], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_rules(*_a, **_k):
            rule = _fake_rule(
                factor_mode="2FA", phishing_resistant="REQUIRED", priority=1
            )
            return ([rule], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=fake_rules,
        ):
            service = Application(provider)

        admin = service.built_in_apps["saasure"]
        assert (
            admin.access_policy.rules[0].possession_phishing_resistant_required is True
        )
        assert admin.access_policy.rules[0].factor_mode == "2FA"

    def test_network_zone_condition_picked_up_from_rule(self):
        provider = set_mocked_okta_provider()
        app = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-net",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            if "saasure" in kwargs.get("filter", ""):
                return ([app], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_rules(*_a, **_k):
            rule = _fake_rule(
                priority=1,
                access="DENY",
                network_connection="ZONE",
                network_exclude=["zone-blocked"],
            )
            return ([rule], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=fake_rules,
        ):
            service = Application(provider)

        admin = service.built_in_apps["saasure"]
        assert admin.access_policy.rules[0].access == "DENY"
        assert admin.access_policy.rules[0].network_connection == "ZONE"
        assert admin.access_policy.rules[0].network_zones_exclude == ["zone-blocked"]

    def test_optional_phishing_resistant_not_treated_as_required(self):
        provider = set_mocked_okta_provider()
        app = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-opt",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            if "saasure" in kwargs.get("filter", ""):
                return ([app], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_rules(*_a, **_k):
            rule = _fake_rule(
                factor_mode="2FA", phishing_resistant="OPTIONAL", priority=1
            )
            return ([rule], _resp({}), None)

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=fake_rules,
        ):
            service = Application(provider)

        admin = service.built_in_apps["saasure"]
        assert (
            admin.access_policy.rules[0].possession_phishing_resistant_required is False
        )

    def test_lists_integrated_apps_on_demand(self):
        provider = set_mocked_okta_provider()
        built_in_admin = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-admin",
            label="Okta Admin Console",
        )
        custom_app = _fake_app(
            "0oacustom",
            "google_workspace",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-custom",
            label="Google Workspace",
        )
        next_link = '<https://acme.okta.com/api/v1/apps?after=cursor-2>; rel="next"'

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_list_applications(*_a, **kwargs):
            name_filter = kwargs.get("filter", "")
            if name_filter:
                if "saasure" in name_filter:
                    return ([built_in_admin], _resp({}), None)
                if "okta_enduser" in name_filter:
                    return ([], _resp({}), None)
            if kwargs.get("after") is None:
                return ([built_in_admin], _resp({"link": next_link}), None)
            return ([custom_app], _resp({}), None)

        async def fake_list_policy_rules(_policy_id, **_k):
            return (
                [_fake_rule(priority=1, network_include=["zone-corp"])],
                _resp({}),
                None,
            )

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_list_applications,
            list_policy_rules=fake_list_policy_rules,
        ):
            service = Application(provider)
            apps = service.integrated_apps

        assert set(apps.keys()) == {"0oaadminconsole", "0oacustom"}
        assert apps["0oacustom"].label == "Google Workspace"
        assert apps["0oacustom"].access_policy_id == "rst-custom"


class Test_Application_service_sdk_validation_fallback:
    """Verifies the raw-JSON fallback for the Okta SDK enum-validator bug.

    The Okta Management API returns values (e.g. lowercase `"password"`
    in `KnowledgeConstraint.types`) that the SDK's pydantic field
    validators reject as ValidationError. Without a fallback the entire
    policy fetch crashes; with the fallback we evaluate the rules
    correctly via raw JSON.
    """

    def _build_service_with_validation_error_then_raw_success(
        self, raw_rules_payload, app_filter_match="saasure"
    ):
        from pydantic import ValidationError

        provider = set_mocked_okta_provider()
        admin = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-admin",
            label="Okta Admin Console",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            if app_filter_match in (kwargs.get("filter") or ""):
                return ([admin], _resp({}), None)
            return ([], _resp({}), None)

        async def failing_list_policy_rules(*_a, **_k):
            try:
                # Trigger a real pydantic ValidationError so we exercise
                # the exact exception type the SDK raises in production.
                from okta.models.knowledge_constraint import KnowledgeConstraint

                KnowledgeConstraint(types=["password"])
            except ValidationError as ve:
                raise ve
            return ([], _resp({}), None)

        async def fake_raw_create(*_a, **_k):
            return ({"url": "/api/v1/policies/rst-admin/rules"}, None)

        async def fake_raw_execute(_request):
            return (None, json.dumps(raw_rules_payload), None)

        sdk_mock = mock.MagicMock()
        sdk_mock.get_first_party_app_settings = fake_settings
        sdk_mock.list_applications = fake_apps
        sdk_mock.list_policy_rules = failing_list_policy_rules
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            from prowler.providers.okta.services.application.application_service import (
                Application as _Application,
            )

            return _Application(provider)

    def test_raw_fallback_projects_factor_mode_and_phishing_resistant(self):
        rules_payload = [
            {
                "id": "rul-1",
                "name": "Top Rule",
                "priority": 1,
                "status": "ACTIVE",
                "system": False,
                "actions": {
                    "appSignOn": {
                        "access": "ALLOW",
                        "verificationMethod": {
                            "type": "ASSURANCE",
                            "factorMode": "2FA",
                            "constraints": [
                                {
                                    "knowledge": {"types": ["password"]},
                                    "possession": {"phishingResistant": "REQUIRED"},
                                }
                            ],
                        },
                    }
                },
                "conditions": {
                    "network": {
                        "connection": "ZONE",
                        "include": ["nzo-corp"],
                        "exclude": [],
                    }
                },
            }
        ]
        service = self._build_service_with_validation_error_then_raw_success(
            rules_payload
        )

        admin = service.built_in_apps["saasure"]
        assert admin.access_policy is not None
        assert len(admin.access_policy.rules) == 1
        rule = admin.access_policy.rules[0]
        assert rule.factor_mode == "2FA"
        assert rule.possession_phishing_resistant_required is True
        assert rule.network_connection == "ZONE"
        assert rule.network_zones_include == ["nzo-corp"]
        assert rule.is_default is False
        assert rule.priority == 1

    def test_raw_fallback_handles_empty_rules(self):
        service = self._build_service_with_validation_error_then_raw_success([])
        admin = service.built_in_apps["saasure"]
        assert admin.access_policy is not None
        assert admin.access_policy.rules == []


class Test_Application_service_per_app_isolation:
    """One app's fetch failure must not erase the other app's findings."""

    def test_dashboard_still_returned_when_admin_console_policy_fetch_fails(self):
        provider = set_mocked_okta_provider()
        admin = _fake_app(
            "0oaadminconsole",
            "saasure",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-broken",
            label="Okta Admin Console",
        )
        dashboard = _fake_app(
            "0oadashboard",
            "okta_enduser",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-dash",
            label="Okta Dashboard",
        )

        async def fake_settings(_app_name):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            f = kwargs.get("filter") or ""
            if "saasure" in f:
                return ([admin], _resp({}), None)
            if "okta_enduser" in f:
                return ([dashboard], _resp({}), None)
            return ([], _resp({}), None)

        async def fake_policy_rules(policy_id, **_k):
            if policy_id == "rst-broken":
                raise RuntimeError("simulated unexpected SDK failure")
            return (
                [
                    _fake_rule(
                        name="Top",
                        priority=1,
                        factor_mode="2FA",
                        phishing_resistant="REQUIRED",
                    )
                ],
                _resp({}),
                None,
            )

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=fake_policy_rules,
        ):
            service = Application(provider)

        # Admin Console: app captured, access_policy set to None due to
        # isolated failure during rule fetch.
        admin_model = service.built_in_apps["saasure"]
        assert admin_model.access_policy is None
        # Dashboard: succeeded — its rule is fully resolved.
        dashboard_model = service.built_in_apps["okta_enduser"]
        assert dashboard_model.access_policy is not None
        assert dashboard_model.access_policy.rules[0].factor_mode == "2FA"

    def test_integrated_apps_one_app_failure_does_not_drop_others(self):
        provider = set_mocked_okta_provider()
        good = _fake_app(
            "0oa-good",
            "custom_good",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-good",
            label="Good App",
        )
        bad = _fake_app(
            "0oa-bad",
            "custom_bad",
            access_policy_href="https://acme.okta.com/api/v1/policies/rst-bad",
            label="Bad App",
        )

        async def fake_settings(_):
            return (_fake_admin_console_settings(), _resp({}), None)

        async def fake_apps(*_a, **kwargs):
            f = kwargs.get("filter") or ""
            if f:
                return ([], _resp({}), None)
            return ([good, bad], _resp({}), None)

        async def fake_policy_rules(policy_id, **_k):
            if policy_id == "rst-bad":
                raise RuntimeError("simulated failure")
            return (
                [_fake_rule(name="Top", priority=1, factor_mode="1FA")],
                _resp({}),
                None,
            )

        with _patch_sdk(
            get_first_party_app_settings=fake_settings,
            list_applications=fake_apps,
            list_policy_rules=fake_policy_rules,
        ):
            service = Application(provider)
            apps = service.integrated_apps

        assert set(apps.keys()) == {"0oa-good", "0oa-bad"}
        assert apps["0oa-good"].access_policy is not None
        assert apps["0oa-bad"].access_policy is None
