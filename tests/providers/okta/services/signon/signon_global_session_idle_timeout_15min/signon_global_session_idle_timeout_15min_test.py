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
    "signon_global_session_idle_timeout_15min."
    "signon_global_session_idle_timeout_15min.signon_client"
)


def _run_check(signon_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=signon_client),
    ):
        from prowler.providers.okta.services.signon.signon_global_session_idle_timeout_15min.signon_global_session_idle_timeout_15min import (
            signon_global_session_idle_timeout_15min,
        )

        return signon_global_session_idle_timeout_15min().execute()


class Test_signon_global_session_idle_timeout_15min:
    def test_no_policies(self):
        findings = _run_check(build_signon_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_is_compliant(self):
        policy = default_policy(
            [
                non_default_rule("Strict 15min", idle_min=15, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Strict 15min" in findings[0].status_extended
        assert "Default Policy" in findings[0].status_extended
        assert "priority 99, default" in findings[0].status_extended

    def test_fail_when_only_default_rule(self):
        policy = default_policy([default_rule(priority=1)])
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "uses 'Default Rule' as its active Priority 1 rule" in (
            findings[0].status_extended
        )

    def test_fail_when_priority_one_non_default_rule_has_null_idle(self):
        policy = default_policy(
            [
                GlobalSessionPolicyRule(
                    id="rule-no-session",
                    name="No Session Block",
                    priority=1,
                    status="ACTIVE",
                    is_default=False,
                    max_session_idle_minutes=None,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No Session Block" in findings[0].status_extended
        assert "does not define" in findings[0].status_extended

    def test_fail_when_priority_one_non_default_rule_exceeds_threshold(self):
        policy = default_policy(
            [
                non_default_rule("Loose 60min", idle_min=60, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Loose 60min" in findings[0].status_extended
        assert "exceeding the configured threshold" in findings[0].status_extended

    def test_fail_when_compliant_non_default_rule_is_not_priority_one(self):
        policy = default_policy(
            [
                default_rule(priority=1),
                non_default_rule("Strict 15min", idle_min=15, priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "uses 'Default Rule' as its active Priority 1 rule" in (
            findings[0].status_extended
        )

    def test_emits_one_finding_per_policy(self):
        # Custom policy at priority 1 with a permissive rule + Default Policy
        # with a strict rule -> two findings, ordered by policy priority.
        admins_policy = custom_policy(
            [
                non_default_rule("Admin Loose", idle_min=120, priority=1),
                default_rule(priority=2),
            ],
            name="Admins Policy",
        )
        strict_default = default_policy(
            [
                non_default_rule("Strict 15min", idle_min=15, priority=1),
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
        assert "priority 99, default" in by_name["Default Policy"].status_extended

    def test_inactive_policy_is_skipped(self):
        inactive = GlobalSessionPolicy(
            id="pol-inactive",
            name="Disabled Policy",
            priority=1,
            status="INACTIVE",
            is_default=False,
            rules=[non_default_rule("Loose 120min", idle_min=120, priority=1)],
        )
        active_default = default_policy(
            [
                non_default_rule("Strict 15min", idle_min=15, priority=1),
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
            rules=[non_default_rule("Strict 15min", idle_min=15, priority=1)],
        )
        findings = _run_check(build_signon_client({"pol-default": only_inactive}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        policy = default_policy(
            [
                non_default_rule("Relaxed 30min", idle_min=30, priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(
            build_signon_client(
                {"pol-default": policy},
                audit_config={"okta_max_session_idle_minutes": 60},
            )
        )
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "threshold of 60 minutes" in findings[0].status_extended
