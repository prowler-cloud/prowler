from unittest.mock import patch

import pytest

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)

CHECK_CLIENT = (
    "prowler.providers.googleworkspace.services.security."
    "security_2sv_enforced.security_2sv_enforced.security_client"
)

# A domain that satisfies every step of the CIS audit procedure.
COMPLIANT = dict(
    two_sv_enforced_from="2026-05-25T15:27:52.352Z",
    two_sv_allow_enrollment=True,
    two_sv_enrollment_grace_period="1209600s",
    two_sv_allow_trusting_device=False,
    # Security keys exclude verification codes via text and phone call.
    two_sv_allowed_factor_set="PASSKEY_ONLY",
)


def run_check(policies_fetched=True, **overrides):
    mock_provider = set_mocked_googleworkspace_provider()

    with (
        patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=mock_provider,
        ),
        patch(CHECK_CLIENT) as mock_client,
    ):
        from prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced import (
            security_2sv_enforced,
        )

        mock_client.provider = mock_provider
        mock_client.policies_fetched = policies_fetched
        mock_client.policies = SecurityPolicies(**overrides)

        return security_2sv_enforced().execute()


class TestSecurity2svEnforced:
    def test_pass_full_audit_procedure_met(self):
        """PASS when every step of the CIS audit procedure is satisfied"""
        findings = run_check(**COMPLIANT)

        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "is enforced" in findings[0].status_extended
        assert findings[0].resource_name == "Security Policies"
        assert findings[0].resource_id == "securityPolicies"
        assert findings[0].customer_id == CUSTOMER_ID

    @pytest.mark.parametrize(
        "factor_set", ["NO_TELEPHONY", "PASSKEY_ONLY", "PASSKEY_PLUS_SECURITY_CODE"]
    )
    def test_pass_any_method_that_excludes_telephony(self, factor_set):
        """CIS asks for any method except verification codes via text or phone call"""
        findings = run_check(**{**COMPLIANT, "two_sv_allowed_factor_set": factor_set})

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_pass_no_enrollment_period(self):
        """PASS when there is no enrollment period, which is stricter than 2 weeks"""
        findings = run_check(**{**COMPLIANT, "two_sv_enrollment_grace_period": "0s"})

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"two_sv_enforced_from": None}, "not configured"),
            ({"two_sv_enforced_from": ""}, "not configured"),
            ({"two_sv_enforced_from": "1970-01-01T00:00:00Z"}, "OFF"),
            ({"two_sv_allow_enrollment": False}, "not allowed to turn on"),
            (
                {"two_sv_enrollment_grace_period": "2592000s"},
                "enrollment period is 30 day(s)",
            ),
            ({"two_sv_allow_trusting_device": True}, "trust their device"),
            (
                {"two_sv_allow_trusting_device": None},
                "device trust is not configured",
            ),
            (
                {"two_sv_enforced_from": "2099-01-01T00:00:00Z"},
                "enforcement does not start until 2099-01-01T00:00:00Z",
            ),
            (
                {"two_sv_enforced_from": "not-a-date"},
                "enforcement start date 'not-a-date' could not be read",
            ),
            (
                {"two_sv_enrollment_grace_period": "28d"},
                "enrollment period '28d' could not be read",
            ),
            (
                {"two_sv_allowed_factor_set": "ALL"},
                "the allowed methods are ALL",
            ),
            (
                {"two_sv_allowed_factor_set": "SOME_FUTURE_ENUM"},
                "the allowed methods are SOME_FUTURE_ENUM",
            ),
            (
                {"two_sv_allowed_factor_set": None},
                "allowed methods are not configured",
            ),
        ],
    )
    def test_fail_each_audit_step(self, overrides, expected):
        """FAIL when any single step of the CIS audit procedure is not met"""
        findings = run_check(**{**COMPLIANT, **overrides})

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert expected in findings[0].status_extended

    def test_fail_reports_every_issue(self):
        """A domain left on Google's defaults reports all the failing steps"""
        findings = run_check(two_sv_enforced_from=None)

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "enforcement is not configured" in findings[0].status_extended
        assert "device trust is not configured" in findings[0].status_extended
        assert "allowed methods are not configured" in findings[0].status_extended

    def test_manual_when_a_group_or_sub_ou_overrides_a_passing_policy(self):
        """A passing domain-wide policy cannot be confirmed for the overridden users"""
        findings = run_check(
            **{
                **COMPLIANT,
                "overridden_settings": {"security.two_step_verification_enforcement"},
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "security.two_step_verification_enforcement is also overridden" in (
            findings[0].status_extended
        )

    def test_a_domain_wide_failure_is_reported_even_with_an_override(self):
        """Whoever no override reaches still gets the failing domain-wide policy"""
        findings = run_check(
            **{
                **COMPLIANT,
                "two_sv_enforced_from": None,
                "overridden_settings": {
                    "security.two_step_verification_enforcement_factor"
                },
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "enforcement is not configured" in findings[0].status_extended

    def test_manual_when_several_settings_are_overridden(self):
        findings = run_check(
            **{
                **COMPLIANT,
                "overridden_settings": [
                    "security.two_step_verification_device_trust",
                    "security.two_step_verification_enforcement",
                ],
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert (
            "security.two_step_verification_device_trust, "
            "security.two_step_verification_enforcement are also overridden"
        ) in findings[0].status_extended

    def test_manual_when_a_setting_only_exists_below_the_domain(self):
        """No domain-wide value was reported, so the defaults would fabricate issues"""
        findings = run_check(
            **{
                **COMPLIANT,
                "two_sv_enforced_from": None,
                "overridden_settings": ["security.two_step_verification_enforcement"],
                "unobserved_settings": ["security.two_step_verification_enforcement"],
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "no domain-wide value was reported" in findings[0].status_extended

    def test_manual_when_the_policy_scope_could_not_be_resolved(self):
        """Every value was dropped, so none of them can be judged"""
        findings = run_check(**{**COMPLIANT, "unresolved_scope": True})

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "root organizational unit could not be resolved" in (
            findings[0].status_extended
        )

    def test_a_failure_keeps_the_override_caveat(self):
        findings = run_check(
            **{
                **COMPLIANT,
                "two_sv_allow_trusting_device": True,
                "overridden_settings": ["security.two_step_verification_enforcement"],
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "trust their device" in findings[0].status_extended
        assert "also overridden" in findings[0].status_extended

    def test_manual_when_every_failing_setting_is_overridden(self):
        """The overriding value is not exposed, so the failure is unconfirmed"""
        findings = run_check(
            **{
                **COMPLIANT,
                "two_sv_allow_trusting_device": True,
                "overridden_settings": ["security.two_step_verification_device_trust"],
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "trust their device" in findings[0].status_extended
        assert "every failing setting is also overridden" in (
            findings[0].status_extended
        )

    def test_fail_when_only_some_failing_settings_are_overridden(self):
        """A failure no override reaches is still proven for the whole domain"""
        findings = run_check(
            **{
                **COMPLIANT,
                "two_sv_allow_trusting_device": True,
                "two_sv_allowed_factor_set": "ALL",
                "overridden_settings": ["security.two_step_verification_device_trust"],
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "the allowed methods are ALL" in findings[0].status_extended

    def test_an_override_on_a_setting_this_check_ignores_does_not_apply(self):
        """The sign-in code setting belongs to 4.1.1.2, not to 4.1.1.1 or 4.1.1.3"""
        findings = run_check(
            **{
                **COMPLIANT,
                "overridden_settings": {"security.two_step_verification_sign_in_code"},
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_no_findings_when_fetch_failed(self):
        """No findings returned when the API fetch failed"""
        assert run_check(policies_fetched=False) == []
