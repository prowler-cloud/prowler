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


class Test_signon_global_session_idle_timeout_15min:
    def test_no_policies(self):
        signon_client = build_signon_client({})
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

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "was not found" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_is_compliant(self):
        policy = default_policy(
            [
                non_default_rule("Strict 15min", idle_min=15, priority=1),
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
            from prowler.providers.okta.services.signon.signon_global_session_idle_timeout_15min.signon_global_session_idle_timeout_15min import (
                signon_global_session_idle_timeout_15min,
            )

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "Strict 15min" in findings[0].status_extended
            assert "Priority 1 non-default rule" in findings[0].status_extended

    def test_fail_when_only_default_rule(self):
        policy = default_policy([default_rule(priority=1)])
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_idle_timeout_15min().execute()
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_idle_timeout_15min().execute()
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_idle_timeout_15min().execute()
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "uses 'Default Rule' as its active Priority 1 rule" in (
                findings[0].status_extended
            )

    def test_ignores_other_custom_policies(self):
        default_policy_with_strict_rule = default_policy(
            [
                non_default_rule("Strict 15min", idle_min=15, priority=1),
                default_rule(priority=2),
            ]
        )
        custom_loose_policy = custom_policy(
            [
                non_default_rule("Loose Admin Rule", idle_min=60, priority=1),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client(
            {
                "pol-custom": custom_loose_policy,
                "pol-default": default_policy_with_strict_rule,
            }
        )
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

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].resource_name == "Default Policy"

    def test_fail_when_default_policy_is_inactive(self):
        policy = GlobalSessionPolicy(
            id="pol-default",
            name="Default Policy",
            priority=99,
            status="INACTIVE",
            is_default=True,
            rules=[non_default_rule("Strict 15min", idle_min=15, priority=1)],
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "status 'INACTIVE'" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        policy = default_policy(
            [
                non_default_rule("Relaxed 30min", idle_min=30, priority=1),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client(
            {"pol-default": policy},
            audit_config={"okta_max_session_idle_minutes": 60},
        )
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

            findings = signon_global_session_idle_timeout_15min().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "threshold of 60 minutes" in findings[0].status_extended
