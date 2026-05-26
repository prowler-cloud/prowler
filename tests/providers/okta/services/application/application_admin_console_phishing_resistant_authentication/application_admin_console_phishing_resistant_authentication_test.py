from unittest import mock

from prowler.providers.okta.services.application.application_service import (
    ADMIN_CONSOLE_APP_NAME,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.application.application_fixtures import (
    admin_console_app,
    auth_policy_rule,
    build_application_client,
    catch_all_rule,
)

CHECK_PATH = (
    "prowler.providers.okta.services.application."
    "application_admin_console_phishing_resistant_authentication."
    "application_admin_console_phishing_resistant_authentication.application_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.application.application_admin_console_phishing_resistant_authentication.application_admin_console_phishing_resistant_authentication import (
            application_admin_console_phishing_resistant_authentication,
        )

        return application_admin_console_phishing_resistant_authentication().execute()


class Test_application_admin_console_phishing_resistant_authentication:
    def test_pass_when_top_rule_requires_phishing_resistant(self):
        app = admin_console_app(
            rules=[
                auth_policy_rule(
                    name="Phishing Resistant", priority=1, phishing_resistant=True
                ),
                catch_all_rule(priority=2),
            ]
        )
        client = build_application_client(built_in_apps={ADMIN_CONSOLE_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "Phishing Resistant" in findings[0].status_extended

    def test_fail_when_top_rule_does_not_require(self):
        app = admin_console_app(
            rules=[
                auth_policy_rule(
                    name="Loose Rule", priority=1, phishing_resistant=False
                ),
                catch_all_rule(priority=2),
            ]
        )
        client = build_application_client(built_in_apps={ADMIN_CONSOLE_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "does not enforce phishing-resistant" in findings[0].status_extended

    def test_pass_when_top_rule_is_default_and_requires_phishing_resistant(self):
        app = admin_console_app(
            rules=[catch_all_rule(priority=1, phishing_resistant=True)]
        )
        client = build_application_client(built_in_apps={ADMIN_CONSOLE_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "Catch-all Rule" in findings[0].status_extended
        assert "built-in Catch-all Rule" in findings[0].status_extended

    def test_fail_when_no_priority_one_rule(self):
        app = admin_console_app(
            rules=[
                auth_policy_rule(
                    name="Phishing Resistant", priority=2, phishing_resistant=True
                ),
                catch_all_rule(priority=3),
            ]
        )
        client = build_application_client(built_in_apps={ADMIN_CONSOLE_APP_NAME: app})
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "no Priority 1 active rule" in findings[0].status_extended

    def test_fail_when_no_access_policy_bound(self):
        app = admin_console_app(rules=[], access_policy_id=None)
        client = build_application_client(built_in_apps={ADMIN_CONSOLE_APP_NAME: app})
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
