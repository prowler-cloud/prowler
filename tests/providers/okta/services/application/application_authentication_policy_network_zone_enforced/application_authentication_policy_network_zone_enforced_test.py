from unittest import mock

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.application.application_fixtures import (
    auth_policy_rule,
    build_application_client,
    catch_all_rule,
    integrated_app,
)

CHECK_PATH = (
    "prowler.providers.okta.services.application."
    "application_authentication_policy_network_zone_enforced."
    "application_authentication_policy_network_zone_enforced.application_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=client),
    ):
        from prowler.providers.okta.services.application.application_authentication_policy_network_zone_enforced.application_authentication_policy_network_zone_enforced import (
            application_authentication_policy_network_zone_enforced,
        )

        return application_authentication_policy_network_zone_enforced().execute()


class Test_application_authentication_policy_network_zone_enforced:
    def test_pass_when_all_active_nondefault_rules_are_zoned_and_catch_all_denies(self):
        app = integrated_app(
            "0oa-google",
            "google_workspace",
            label="Google Workspace",
            rules=[
                auth_policy_rule(
                    name="Allow Corp",
                    priority=1,
                    network_connection="ZONE",
                    network_zones_include=["zone-corp"],
                ),
                auth_policy_rule(
                    name="Block Risky",
                    priority=2,
                    network_connection="ZONE",
                    network_zones_exclude=["zone-risky"],
                ),
                catch_all_rule(priority=3, access="DENY"),
            ],
        )
        findings = _run_check(build_application_client(integrated_apps={app.id: app}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Google Workspace" in findings[0].status_extended
        assert "Catch-all Rule" in findings[0].status_extended

    def test_fail_when_nondefault_rule_has_no_network_zone(self):
        app = integrated_app(
            "0oa-salesforce",
            "salesforce",
            label="Salesforce",
            rules=[
                auth_policy_rule(name="Allow Users", priority=1),
                catch_all_rule(priority=2, access="DENY"),
            ],
        )
        findings = _run_check(build_application_client(integrated_apps={app.id: app}))
        assert findings[0].status == "FAIL"
        assert "without Network Zones" in findings[0].status_extended
        assert "Allow Users" in findings[0].status_extended

    def test_fail_when_catch_all_rule_does_not_deny(self):
        app = integrated_app(
            "0oa-box",
            "box",
            label="Box",
            rules=[
                auth_policy_rule(
                    name="Allow Corp",
                    priority=1,
                    network_connection="ZONE",
                    network_zones_include=["zone-corp"],
                ),
                catch_all_rule(priority=2, access="ALLOW"),
            ],
        )
        findings = _run_check(build_application_client(integrated_apps={app.id: app}))
        assert findings[0].status == "FAIL"
        assert "`Access is` to `DENY`" in findings[0].status_extended

    def test_fail_when_no_active_nondefault_rules_exist(self):
        app = integrated_app(
            "0oa-slack",
            "slack",
            label="Slack",
            rules=[catch_all_rule(priority=1, access="DENY")],
        )
        findings = _run_check(build_application_client(integrated_apps={app.id: app}))
        assert findings[0].status == "FAIL"
        assert "no active non-default rules" in findings[0].status_extended

    def test_fail_when_no_access_policy_is_bound(self):
        app = integrated_app(
            "0oa-zoom",
            "zoom",
            label="Zoom",
            rules=[],
            access_policy_id=None,
        )
        findings = _run_check(build_application_client(integrated_apps={app.id: app}))
        assert findings[0].status == "FAIL"
        assert "no Authentication Policy bound" in findings[0].status_extended

    def test_inactive_apps_are_skipped(self):
        inactive = integrated_app(
            "0oa-inactive",
            "dropbox",
            label="Dropbox",
            status="INACTIVE",
            rules=[
                auth_policy_rule(
                    name="Allow Corp",
                    priority=1,
                    network_connection="ZONE",
                    network_zones_include=["zone-corp"],
                ),
                catch_all_rule(priority=2, access="DENY"),
            ],
        )
        active = integrated_app(
            "0oa-active",
            "github",
            label="GitHub",
            rules=[
                auth_policy_rule(
                    name="Allow Corp",
                    priority=1,
                    network_connection="ZONE",
                    network_zones_include=["zone-corp"],
                ),
                catch_all_rule(priority=2, access="DENY"),
            ],
        )
        findings = _run_check(
            build_application_client(
                integrated_apps={inactive.id: inactive, active.id: active}
            )
        )
        assert len(findings) == 1
        assert findings[0].resource_name == "GitHub"
        assert findings[0].status == "PASS"

    def test_manual_when_apps_scope_missing(self):
        findings = _run_check(
            build_application_client(
                missing_scope={
                    "admin_console_app_settings": None,
                    "built_in_apps": None,
                    "integrated_apps": "okta.apps.read",
                    "access_policies": None,
                }
            )
        )
        assert findings[0].status == "MANUAL"
        assert "okta.apps.read" in findings[0].status_extended

    def test_manual_when_policy_scope_missing(self):
        findings = _run_check(
            build_application_client(
                missing_scope={
                    "admin_console_app_settings": None,
                    "built_in_apps": None,
                    "integrated_apps": None,
                    "access_policies": "okta.policies.read",
                }
            )
        )
        assert findings[0].status == "MANUAL"
        assert "okta.policies.read" in findings[0].status_extended

    def test_manual_when_no_active_apps_returned(self):
        findings = _run_check(build_application_client(integrated_apps={}))
        assert findings[0].status == "MANUAL"
        assert "No active Okta applications" in findings[0].status_extended
