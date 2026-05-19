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


class Test_signon_global_session_cookies_not_persistent:
    def test_no_policies(self):
        signon_client = build_signon_client({})
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

            findings = signon_global_session_cookies_not_persistent().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "was not found" in findings[0].status_extended

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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_cookies_not_persistent().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disables persistent global session cookies" in (
                findings[0].status_extended
            )

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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_cookies_not_persistent().execute()
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
        signon_client = build_signon_client({"pol-default": policy})
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

            findings = signon_global_session_cookies_not_persistent().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "does not" in findings[0].status_extended
            assert "assert" in findings[0].status_extended

    def test_fail_when_default_policy_is_inactive(self):
        policy = GlobalSessionPolicy(
            id="pol-default",
            name="Default Policy",
            priority=99,
            status="INACTIVE",
            is_default=True,
            rules=[
                non_default_rule(
                    "Compliant",
                    use_persistent_cookie=False,
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
            from prowler.providers.okta.services.signon.signon_global_session_cookies_not_persistent.signon_global_session_cookies_not_persistent import (
                signon_global_session_cookies_not_persistent,
            )

            findings = signon_global_session_cookies_not_persistent().execute()
            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "status 'INACTIVE'" in findings[0].status_extended

    def test_ignores_other_custom_policies(self):
        compliant_default = default_policy(
            [
                non_default_rule(
                    "Non-persistent",
                    use_persistent_cookie=False,
                    priority=1,
                ),
                default_rule(priority=2),
            ]
        )
        permissive_custom = custom_policy(
            [
                non_default_rule(
                    "Sticky admin",
                    use_persistent_cookie=True,
                    priority=1,
                )
            ]
        )
        signon_client = build_signon_client(
            {"pol-custom": permissive_custom, "pol-default": compliant_default}
        )
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

            findings = signon_global_session_cookies_not_persistent().execute()
            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].resource_name == "Default Policy"
