from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.signon.signon_fixtures import (
    build_signon_client,
    custom_policy,
    default_policy,
    default_rule,
    non_default_rule,
)

CHECK_PATH = (
    "prowler.providers.okta.services.signon."
    "signon_global_session_cookies_not_persistent."
    "signon_global_session_cookies_not_persistent.signon_client"
)


def _run_check(signon_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=signon_client),
    ):
        from prowler.providers.okta.services.signon.signon_global_session_cookies_not_persistent.signon_global_session_cookies_not_persistent import (
            signon_global_session_cookies_not_persistent,
        )

        return signon_global_session_cookies_not_persistent().execute()


class Test_signon_global_session_cookies_not_persistent:
    def test_no_policies(self):
        findings = _run_check(build_signon_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_pass_when_priority_one_rule_disables_persistent_cookies(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Non-persistent cookies",
                    use_persistent_cookie=False,
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "disables persistent global session cookies" in (
            findings[0].status_extended
        )
        assert "priority 99, default" in findings[0].status_extended

    def test_fail_when_priority_one_rule_uses_persistent_cookies(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Persistent cookies enabled",
                    use_persistent_cookie=True,
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "allows persistent global session cookies" in (
            findings[0].status_extended
        )

    def test_fail_when_priority_one_rule_does_not_assert_setting(self):
        policy = default_policy(
            [
                GlobalSessionPolicyRule(
                    id="rule-no-session",
                    name="No Session Block",
                    priority=1,
                    status="ACTIVE",
                    is_default=False,
                    use_persistent_cookie=None,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "does not assert" in findings[0].status_extended

    def test_emits_one_finding_per_policy(self):
        admins_policy = custom_policy(
            [
                non_default_rule(
                    "Sticky admin",
                    use_persistent_cookie=True,
                    priority=1,
                )
            ],
            name="Admins Policy",
        )
        strict_default = default_policy(
            [
                non_default_rule(
                    "Non-persistent",
                    use_persistent_cookie=False,
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(
            build_signon_client(
                {"pol-custom": admins_policy, "pol-default": strict_default}
            )
        )
        assert len(findings) == 2
        by_name = {f.resource_name: f for f in findings}
        assert by_name["Admins Policy"].status == "FAIL"
        assert "priority 1, custom" in by_name["Admins Policy"].status_extended
        assert by_name["Default Policy"].status == "PASS"

    def test_inactive_policy_is_skipped(self):
        inactive = GlobalSessionPolicy(
            id="pol-inactive",
            name="Disabled Policy",
            priority=1,
            status="INACTIVE",
            is_default=False,
            rules=[non_default_rule("Sticky", use_persistent_cookie=True, priority=1)],
        )
        active_default = default_policy(
            [
                non_default_rule(
                    "Non-persistent",
                    use_persistent_cookie=False,
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(
            build_signon_client(
                {"pol-inactive": inactive, "pol-default": active_default}
            )
        )
        assert len(findings) == 1
        assert findings[0].resource_name == "Default Policy"
        assert findings[0].status == "PASS"

    def test_fail_when_all_policies_inactive(self):
        only_inactive = GlobalSessionPolicy(
            id="pol-default",
            name="Default Policy",
            priority=99,
            status="INACTIVE",
            is_default=True,
            rules=[
                non_default_rule("Compliant", use_persistent_cookie=False, priority=1)
            ],
        )
        findings = _run_check(build_signon_client({"pol-default": only_inactive}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended
