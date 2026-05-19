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
    "signon_global_session_lifetime_18h."
    "signon_global_session_lifetime_18h.signon_client"
)


def _run_check(signon_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=signon_client),
    ):
        from prowler.providers.okta.services.signon.signon_global_session_lifetime_18h.signon_global_session_lifetime_18h import (
            signon_global_session_lifetime_18h,
        )

        return signon_global_session_lifetime_18h().execute()


class Test_signon_global_session_lifetime_18h:
    def test_no_policies(self):
        findings = _run_check(build_signon_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_is_compliant(self):
        policy = default_policy(
            [
                non_default_rule("18h rule", lifetime_min=1080, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "18h rule" in findings[0].status_extended
        assert "1080 minutes" in findings[0].status_extended
        assert "priority 99, default" in findings[0].status_extended

    def test_fail_when_lifetime_exceeds_threshold(self):
        policy = default_policy(
            [
                non_default_rule("Loose 24h rule", lifetime_min=1440, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "1440 minutes" in findings[0].status_extended
        assert "exceeding the configured threshold" in findings[0].status_extended

    def test_fail_when_priority_one_rule_has_no_lifetime(self):
        policy = default_policy(
            [
                GlobalSessionPolicyRule(
                    id="rule-no-session",
                    name="No Session Block",
                    priority=1,
                    status="ACTIVE",
                    is_default=False,
                    max_session_lifetime_minutes=None,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "does not define" in findings[0].status_extended

    def test_fail_when_lifetime_is_disabled_with_zero(self):
        policy = default_policy(
            [
                non_default_rule("Unlimited Lifetime", lifetime_min=0, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "0 minutes" in findings[0].status_extended
        assert "disables the maximum Okta global session lifetime" in (
            findings[0].status_extended
        )

    def test_fail_when_default_rule_is_priority_one(self):
        policy = default_policy(
            [
                default_rule(priority=1, lifetime_min=1080),
                non_default_rule("Compliant", lifetime_min=1080, priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "uses 'Default Rule' as its active Priority 1 rule" in (
            findings[0].status_extended
        )

    def test_emits_one_finding_per_policy(self):
        admins_policy = custom_policy(
            [
                non_default_rule("Admin Long Lived", lifetime_min=2880, priority=1),
                default_rule(priority=2),
            ],
            name="Admins Policy",
        )
        strict_default = default_policy(
            [
                non_default_rule("18h rule", lifetime_min=1080, priority=1),
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
            rules=[non_default_rule("Loose", lifetime_min=2880, priority=1)],
        )
        active_default = default_policy(
            [
                non_default_rule("18h rule", lifetime_min=1080, priority=1),
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
            rules=[non_default_rule("18h rule", lifetime_min=1080, priority=1)],
        )
        findings = _run_check(build_signon_client({"pol-default": only_inactive}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        policy = default_policy(
            [
                non_default_rule("Relaxed 24h", lifetime_min=1440, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(
            build_signon_client(
                {"pol-default": policy},
                audit_config={"okta_max_session_lifetime_minutes": 1440},
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "threshold of 1440 minutes" in findings[0].status_extended
