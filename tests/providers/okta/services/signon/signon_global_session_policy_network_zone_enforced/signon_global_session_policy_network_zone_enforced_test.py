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
    "signon_global_session_policy_network_zone_enforced."
    "signon_global_session_policy_network_zone_enforced.signon_client"
)


def _run_check(signon_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(CHECK_PATH, new=signon_client),
    ):
        from prowler.providers.okta.services.signon.signon_global_session_policy_network_zone_enforced.signon_global_session_policy_network_zone_enforced import (
            signon_global_session_policy_network_zone_enforced,
        )

        return signon_global_session_policy_network_zone_enforced().execute()


class Test_signon_global_session_policy_network_zone_enforced:
    def test_no_policies(self):
        findings = _run_check(build_signon_client({}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_includes_zone(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Allow-from-VPN",
                    network_zones_include=["zone-corp"],
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Allow-from-VPN" in findings[0].status_extended
        assert "non-default rule" in findings[0].status_extended
        assert "priority 99, default" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_excludes_zone(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Block-blacklist",
                    network_zones_exclude=["zone-blocked"],
                    priority=1,
                ),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Block-blacklist" in findings[0].status_extended

    def test_pass_when_only_default_rule_has_zones(self):
        policy = default_policy(
            [
                GlobalSessionPolicyRule(
                    id="rule-default-zoned",
                    name="Default Rule",
                    priority=1,
                    status="ACTIVE",
                    is_default=True,
                    network_zones_include=["zone-corp"],
                ),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "built-in Default Rule" in findings[0].status_extended

    def test_fail_when_priority_one_rule_has_no_zones(self):
        policy = default_policy(
            [
                non_default_rule("Plain non-default", priority=1),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "Plain non-default" in findings[0].status_extended
        assert "does not map" in findings[0].status_extended

    def test_fail_when_only_lower_priority_rule_has_zones(self):
        policy = default_policy(
            [
                non_default_rule("No-zones top", priority=1),
                non_default_rule(
                    "Zoned-but-low",
                    network_zones_include=["zone-corp"],
                    priority=2,
                ),
                default_rule(priority=3),
            ]
        )
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No-zones top" in findings[0].status_extended

    def test_fail_when_only_default_rule_has_no_zones(self):
        policy = default_policy([default_rule(priority=1)])
        findings = _run_check(build_signon_client({"pol-default": policy}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "built-in Default Rule" in findings[0].status_extended

    def test_emits_one_finding_per_policy(self):
        admins_policy = custom_policy(
            [
                non_default_rule("No-zones admin", priority=1),
                default_rule(priority=2),
            ],
            name="Admins Policy",
        )
        zoned_default = default_policy(
            [
                non_default_rule(
                    "Allow-corp",
                    network_zones_include=["zone-corp"],
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        findings = _run_check(
            build_signon_client(
                {"pol-custom": admins_policy, "pol-default": zoned_default}
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
            rules=[non_default_rule("No-zones", priority=1)],
        )
        active_default = default_policy(
            [
                non_default_rule(
                    "Allow-corp",
                    network_zones_include=["zone-corp"],
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
                non_default_rule(
                    "Allow-corp",
                    network_zones_include=["zone-corp"],
                    priority=1,
                )
            ],
        )
        findings = _run_check(build_signon_client({"pol-default": only_inactive}))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Global Session Policies" in findings[0].status_extended
