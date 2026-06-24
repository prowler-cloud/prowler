from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.application.application_fixtures import (
    admin_console_settings,
    build_application_client,
)

CHECK_PATH = (
    "prowler.providers.okta.services.application."
    "application_admin_console_session_idle_timeout_15min."
    "application_admin_console_session_idle_timeout_15min.application_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.application.application_admin_console_session_idle_timeout_15min.application_admin_console_session_idle_timeout_15min import (
            application_admin_console_session_idle_timeout_15min,
        )

        return application_admin_console_session_idle_timeout_15min().execute()


class Test_application_admin_console_session_idle_timeout_15min:
    def test_pass_at_threshold(self):
        client = build_application_client(
            admin_console_settings=admin_console_settings(idle_timeout=15)
        )
        findings = _run_check(client)
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "15 minutes" in findings[0].status_extended

    def test_pass_below_threshold(self):
        client = build_application_client(
            admin_console_settings=admin_console_settings(idle_timeout=10)
        )
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "10 minutes" in findings[0].status_extended

    def test_fail_above_threshold(self):
        client = build_application_client(
            admin_console_settings=admin_console_settings(idle_timeout=60)
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "exceeding the configured threshold" in findings[0].status_extended

    def test_fail_when_idle_timeout_missing(self):
        client = build_application_client(
            admin_console_settings=admin_console_settings(idle_timeout=None)
        )
        findings = _run_check(client)
        assert findings[0].status == "FAIL"
        assert "does not define" in findings[0].status_extended

    def test_manual_when_settings_unavailable(self):
        client = build_application_client(admin_console_settings=None)
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "Could not retrieve" in findings[0].status_extended

    def test_manual_when_scope_missing(self):
        client = build_application_client(
            missing_scope={
                "admin_console_app_settings": "okta.apps.read",
                "built_in_apps": None,
                "access_policies": None,
            }
        )
        findings = _run_check(client)
        assert findings[0].status == "MANUAL"
        assert "okta.apps.read" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        client = build_application_client(
            admin_console_settings=admin_console_settings(idle_timeout=30),
            audit_config={"okta_admin_console_idle_timeout_max_minutes": 60},
        )
        findings = _run_check(client)
        assert findings[0].status == "PASS"
        assert "threshold of 60 minutes" in findings[0].status_extended
