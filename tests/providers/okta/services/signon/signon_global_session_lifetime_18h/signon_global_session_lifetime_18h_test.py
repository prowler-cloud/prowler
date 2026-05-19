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


class Test_signon_global_session_lifetime_18h:
    def test_no_policies(self):
        signon_client = build_signon_client({})
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

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "was not found" in findings[0].status_extended

    def test_pass_when_priority_one_non_default_rule_is_compliant(self):
        policy = default_policy(
            [
                non_default_rule("18h rule", lifetime_min=1080, priority=1),
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
            from prowler.providers.okta.services.signon.signon_global_session_lifetime_18h.signon_global_session_lifetime_18h import (
                signon_global_session_lifetime_18h,
            )

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "18h rule" in findings[0].status_extended
            assert "1080 minutes" in findings[0].status_extended

    def test_fail_when_lifetime_exceeds_threshold(self):
        policy = default_policy(
            [
                non_default_rule("Loose 24h rule", lifetime_min=1440, priority=1),
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
            from prowler.providers.okta.services.signon.signon_global_session_lifetime_18h.signon_global_session_lifetime_18h import (
                signon_global_session_lifetime_18h,
            )

            findings = signon_global_session_lifetime_18h().execute()
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "does not define" in findings[0].status_extended

    def test_fail_when_default_rule_is_priority_one(self):
        policy = default_policy(
            [
                default_rule(priority=1, lifetime_min=1080),
                non_default_rule("Compliant", lifetime_min=1080, priority=2),
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
            from prowler.providers.okta.services.signon.signon_global_session_lifetime_18h.signon_global_session_lifetime_18h import (
                signon_global_session_lifetime_18h,
            )

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "uses 'Default Rule' as its active Priority 1 rule" in (
                findings[0].status_extended
            )

    def test_fail_when_default_policy_is_inactive(self):
        policy = GlobalSessionPolicy(
            id="pol-default",
            name="Default Policy",
            priority=99,
            status="INACTIVE",
            is_default=True,
            rules=[non_default_rule("18h rule", lifetime_min=1080, priority=1)],
        )
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "status 'INACTIVE'" in findings[0].status_extended

    def test_ignores_other_custom_policies(self):
        compliant_default = default_policy(
            [
                non_default_rule("18h rule", lifetime_min=1080, priority=1),
                default_rule(priority=2),
            ]
        )
        loose_custom = custom_policy(
            [
                non_default_rule("Long-lived admin", lifetime_min=4320, priority=1),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client(
            {"pol-custom": loose_custom, "pol-default": compliant_default}
        )
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

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].resource_name == "Default Policy"

    def test_threshold_overridden_via_audit_config(self):
        policy = default_policy(
            [
                non_default_rule("Relaxed 24h", lifetime_min=1440, priority=1),
                default_rule(priority=2),
            ]
        )
        signon_client = build_signon_client(
            {"pol-default": policy},
            audit_config={"okta_max_session_lifetime_minutes": 1440},
        )
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

            findings = signon_global_session_lifetime_18h().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "threshold of 1440 minutes" in findings[0].status_extended
