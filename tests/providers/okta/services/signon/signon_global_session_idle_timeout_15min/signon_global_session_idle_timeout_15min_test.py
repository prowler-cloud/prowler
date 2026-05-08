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
        is_default=True,
        rules=rules,
    )


def _default_rule(idle_min=480):
    return GlobalSessionPolicyRule(
        id="rule-default",
        name="Default Rule",
        is_default=True,
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
            assert findings == []

    def test_pass_when_compliant_non_default_rule_exists(self):
        policy = _default_policy(
            [
                _default_rule(),
                GlobalSessionPolicyRule(
                    id="rule-15",
                    name="Strict 15min",
                    is_default=False,
                    max_session_idle_minutes=15,
                ),
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

    def test_fail_when_only_default_rule(self):
        policy = _default_policy([_default_rule()])
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
            assert "no non-default rules" in findings[0].status_extended

    def test_fail_when_non_default_rule_exceeds_threshold(self):
        policy = _default_policy(
            [
                _default_rule(),
                GlobalSessionPolicyRule(
                    id="rule-loose",
                    name="Loose 60min",
                    is_default=False,
                    max_session_idle_minutes=60,
                ),
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
            assert "none enforces" in findings[0].status_extended

    def test_threshold_overridden_via_audit_config(self):
        # 30-minute rule fails the STIG default of 15, but passes a relaxed
        # threshold of 60 minutes set in audit_config.
        policy = _default_policy(
            [
                _default_rule(),
                GlobalSessionPolicyRule(
                    id="rule-30",
                    name="Relaxed 30min",
                    is_default=False,
                    max_session_idle_minutes=30,
                ),
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
            assert "<= 60 minutes" in findings[0].status_extended
