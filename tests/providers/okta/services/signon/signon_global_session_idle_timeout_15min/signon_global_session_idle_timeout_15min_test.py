from unittest import mock

from prowler.providers.okta.services.signon.signon_service import (
    GlobalSessionPolicy,
    GlobalSessionPolicyRule,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider

CHECK_PATH = (
    "prowler.providers.okta.services.signon."
    "signon_global_session_idle_timeout_15min."
    "signon_global_session_idle_timeout_15min.signon_client"
)


def _build_signon_client(policies, audit_config: dict = None):
    client = mock.MagicMock()
    client.global_session_policies = policies
    client.provider = set_mocked_okta_provider()
    client.audit_config = audit_config or {}
    return client


def _default_policy(rules):
    return GlobalSessionPolicy(
        id="pol-default",
        name="Default Policy",
        priority=99,
        status="ACTIVE",
        is_default=True,
        rules=rules,
    )


def _custom_policy(rules):
    return GlobalSessionPolicy(
        id="pol-custom",
        name="Admins Policy",
        priority=1,
        status="ACTIVE",
        is_default=False,
        rules=rules,
    )


def _default_rule(idle_min=480, priority=2, status="ACTIVE"):
    return GlobalSessionPolicyRule(
        id="rule-default",
        name="Default Rule",
        priority=priority,
        status=status,
        is_default=True,
        max_session_idle_minutes=idle_min,
    )


def _non_default_rule(name, idle_min, priority=1, status="ACTIVE"):
    return GlobalSessionPolicyRule(
        id=f"rule-{name.lower().replace(' ', '-')}",
        name=name,
        priority=priority,
        status=status,
        is_default=False,
        max_session_idle_minutes=idle_min,
    )


class Test_signon_global_session_idle_timeout_15min:
    def test_no_policies(self):
        signon_client = _build_signon_client({})
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
        policy = _default_policy(
            [
                _non_default_rule("Strict 15min", 15, priority=1),
                _default_rule(priority=2),
            ]
        )
        signon_client = _build_signon_client({"pol-default": policy})
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
        policy = _default_policy([_default_rule(priority=1)])
        signon_client = _build_signon_client({"pol-default": policy})
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
        # Rules without a session block leave max_session_idle_minutes as
        # None. The check must treat those as non-compliant — they cannot
        # enforce any timeout.
        policy = _default_policy(
            [
                GlobalSessionPolicyRule(
                    id="rule-no-session",
                    name="No Session Block",
                    priority=1,
                    status="ACTIVE",
                    is_default=False,
                    max_session_idle_minutes=None,
                ),
                _default_rule(priority=2),
            ]
        )
        signon_client = _build_signon_client({"pol-default": policy})
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
        policy = _default_policy(
            [
                _non_default_rule("Loose 60min", 60, priority=1),
                _default_rule(priority=2),
            ]
        )
        signon_client = _build_signon_client({"pol-default": policy})
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
        policy = _default_policy(
            [
                _default_rule(priority=1),
                _non_default_rule("Strict 15min", 15, priority=2),
            ]
        )
        signon_client = _build_signon_client({"pol-default": policy})
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
        default_policy = _default_policy(
            [
                _non_default_rule("Strict 15min", 15, priority=1),
                _default_rule(priority=2),
            ]
        )
        custom_policy = _custom_policy(
            [
                _non_default_rule("Loose Admin Rule", 60, priority=1),
                _default_rule(priority=2),
            ]
        )
        signon_client = _build_signon_client(
            {"pol-custom": custom_policy, "pol-default": default_policy}
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
            rules=[_non_default_rule("Strict 15min", 15, priority=1)],
        )
        signon_client = _build_signon_client({"pol-default": policy})
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
        # 30-minute rule fails the STIG default of 15, but passes a relaxed
        # threshold of 60 minutes set in audit_config.
        policy = _default_policy(
            [
                _non_default_rule("Relaxed 30min", 30, priority=1),
                _default_rule(priority=2),
            ]
        )
        signon_client = _build_signon_client(
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
