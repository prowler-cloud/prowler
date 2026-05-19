from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
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


class Test_signon_global_session_policy_network_zone_enforced:
    def test_no_policies(self):
        signon_client = build_signon_client({})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "was not found" in findings[0].status_extended

    def test_pass_when_active_rule_includes_zone(self):
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "Allow-from-VPN" in findings[0].status_extended

    def test_pass_when_active_rule_excludes_zone(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Block-blacklist",
                    network_zones_exclude=["zone-blocked"],
                    priority=1,
                ),
            ]
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "Block-blacklist" in findings[0].status_extended

    def test_fail_when_no_rule_uses_network_zone(self):
        policy = default_policy(
            [
                non_default_rule("No-zones rule", priority=1),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "no active non-default rule mapping" in findings[0].status_extended

    def test_fail_when_only_default_rule_uses_zones(self):
        # The built-in Default Rule should not be counted as satisfying
        # the STIG even if it carries zone conditions — the STIG requires
        # an explicit non-default rule.
        policy = default_policy(
            [
                GlobalSessionPolicyRule_with_zones(),
            ]
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"

    def test_fail_when_inactive_rule_has_zones(self):
        policy = default_policy(
            [
                non_default_rule(
                    "Inactive zone rule",
                    network_zones_include=["zone-corp"],
                    priority=1,
                    status="INACTIVE",
                ),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"

    def test_fail_when_default_policy_inactive(self):
        policy = GlobalSessionPolicy(
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "status 'INACTIVE'" in findings[0].status_extended

    def test_ignores_zones_on_other_custom_policies(self):
        default_no_zones = default_policy(
            [
                non_default_rule("Plain rule", priority=1),
                default_rule(priority=2),
            ]
        )
        custom_with_zones = custom_policy(
            [
                non_default_rule(
                    "Custom-allow",
                    network_zones_include=["zone-corp"],
                    priority=1,
                )
            ]
        )
        signon_client = build_signon_client(
            {"pol-default": default_no_zones, "pol-custom": custom_with_zones}
        )
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

            findings = signon_global_session_policy_network_zone_enforced().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert findings[0].resource_name == "Default Policy"


def GlobalSessionPolicyRule_with_zones():
    # Built-in Default Rule that still carries zone conditions — the STIG
    # requires the rule to be non-default, so this scenario must FAIL.
    from prowler.providers.okta.services.signon.signon_service import (
        GlobalSessionPolicyRule,
    )

    return GlobalSessionPolicyRule(
        id="rule-default-zoned",
        name="Default Rule",
        priority=1,
        status="ACTIVE",
        is_default=True,
        network_zones_include=["zone-corp"],
    )
