from unittest import mock

from prowler.providers.okta.services.application.application_service import (
    DASHBOARD_APP_NAME,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.application.application_fixtures import (
    auth_policy_rule,
    build_application_client,
    catch_all_rule,
    dashboard_app,
)

CHECK_PATH = (
    "prowler.providers.okta.services.application."
    "application_dashboard_mfa_required."
    "application_dashboard_mfa_required.application_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.application.application_dashboard_mfa_required.application_dashboard_mfa_required import (
            application_dashboard_mfa_required,
        )

        return application_dashboard_mfa_required().execute()


class Test_application_dashboard_mfa_required:
    def test_pass_when_top_rule_enforces_2fa(self):
        app = dashboard_app(
            rules=[
                auth_policy_rule(name="MFA Required", priority=1, factor_mode="2FA"),
                catch_all_rule(priority=2),
            ]
        )
        client = build_application_client(built_in_apps={DASHBOARD_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "MFA Required" in findings[0].status_extended

    def test_fail_when_top_rule_is_1fa(self):
        app = dashboard_app(
            rules=[
                auth_policy_rule(name="Password Only", priority=1, factor_mode="1FA"),
                catch_all_rule(priority=2),
            ]
        )
        client = build_application_client(built_in_apps={DASHBOARD_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "Password Only" in findings[0].status_extended

    def test_pass_when_top_rule_is_default_and_enforces_2fa(self):
        app = dashboard_app(rules=[catch_all_rule(priority=1, factor_mode="2FA")])
        client = build_application_client(built_in_apps={DASHBOARD_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "Catch-all Rule" in findings[0].status_extended
        assert "built-in Catch-all Rule" in findings[0].status_extended

    def test_fail_when_no_access_policy_bound(self):
        app = dashboard_app(rules=[], access_policy_id=None)
        client = build_application_client(built_in_apps={DASHBOARD_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "no Authentication Policy bound" in findings[0].status_extended

    def test_manual_when_app_not_returned(self):
        client = build_application_client(built_in_apps={})
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "not returned by the Okta API" in findings[0].status_extended

    def test_manual_when_apps_scope_missing(self):
        client = build_application_client(
            missing_scope={
                "admin_console_app_settings": None,
                "built_in_apps": "okta.apps.read",
                "integrated_apps": None,
                "access_policies": None,
            }
        )
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "okta.apps.read" in findings[0].status_extended
