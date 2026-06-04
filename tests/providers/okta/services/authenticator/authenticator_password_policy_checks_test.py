from unittest import mock

import pytest

from tests.providers.okta.okta_fixtures import set_mocked_okta_provider
from tests.providers.okta.services.authenticator.authenticator_fixtures import (
    build_authenticator_client,
    password_policy,
)

PASSWORD_POLICY_CHECK_CASES = [
    (
        "authenticator_password_common_password_check",
        "common_password_check",
        True,
        False,
        "common-password dictionary checks",
    ),
    (
        "authenticator_password_complexity_lowercase",
        "min_lower_case",
        1,
        0,
        "at least one lowercase character",
    ),
    (
        "authenticator_password_complexity_number",
        "min_number",
        1,
        0,
        "at least one numeric character",
    ),
    (
        "authenticator_password_complexity_symbol",
        "min_symbol",
        1,
        0,
        "at least one symbol character",
    ),
    (
        "authenticator_password_complexity_uppercase",
        "min_upper_case",
        1,
        0,
        "at least one uppercase character",
    ),
    (
        "authenticator_password_history_5",
        "history_count",
        5,
        4,
        "password history of at least 5 previous passwords",
    ),
    (
        "authenticator_password_lockout_threshold_3",
        "max_attempts",
        3,
        4,
        "password lockout after 3 or fewer failed attempts",
    ),
    (
        "authenticator_password_maximum_age_60d",
        "max_age_days",
        60,
        61,
        "maximum password age of 60 days or less",
    ),
    (
        "authenticator_password_minimum_age_24h",
        "min_age_minutes",
        1440,
        1439,
        "minimum password age of at least 24 hours",
    ),
    (
        "authenticator_password_minimum_length_15",
        "min_length",
        15,
        14,
        "minimum password length of at least 15 characters",
    ),
]


def _run_password_policy_check(check_name: str, authenticator_client):
    check_path = (
        f"prowler.providers.okta.services.authenticator.{check_name}."
        f"{check_name}.authenticator_client"
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_okta_provider(),
        ),
        mock.patch(check_path, new=authenticator_client),
    ):
        module = __import__(
            f"prowler.providers.okta.services.authenticator.{check_name}.{check_name}",
            fromlist=[check_name],
        )
        return getattr(module, check_name)().execute()


class Test_authenticator_password_policy_checks:
    @pytest.mark.parametrize(
        "check_name, field_name, compliant_value, non_compliant_value, expected_phrase",
        PASSWORD_POLICY_CHECK_CASES,
    )
    def test_missing_policies_scope_returns_manual(
        self,
        check_name,
        field_name,
        compliant_value,
        non_compliant_value,
        expected_phrase,
    ):
        findings = _run_password_policy_check(
            check_name,
            build_authenticator_client(
                password_policies={}, missing_scopes=["okta.policies.read"]
            ),
        )

        assert len(findings) == 1
        assert findings[0].status == "MANUAL"
        assert "okta.policies.read" in findings[0].status_extended

    @pytest.mark.parametrize(
        "check_name, field_name, compliant_value, non_compliant_value, expected_phrase",
        PASSWORD_POLICY_CHECK_CASES,
    )
    def test_no_active_password_policies_fails(
        self,
        check_name,
        field_name,
        compliant_value,
        non_compliant_value,
        expected_phrase,
    ):
        findings = _run_password_policy_check(
            check_name, build_authenticator_client(password_policies={})
        )

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "No active Okta Password Policies" in findings[0].status_extended
        assert expected_phrase in findings[0].status_extended

    @pytest.mark.parametrize(
        "check_name, field_name, compliant_value, non_compliant_value, expected_phrase",
        PASSWORD_POLICY_CHECK_CASES,
    )
    def test_compliant_password_policy_passes(
        self,
        check_name,
        field_name,
        compliant_value,
        non_compliant_value,
        expected_phrase,
    ):
        policy = password_policy(**{field_name: compliant_value})
        findings = _run_password_policy_check(
            check_name,
            build_authenticator_client(password_policies={policy.id: policy}),
        )

        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert findings[0].resource_id == policy.id
        assert expected_phrase in findings[0].status_extended

    @pytest.mark.parametrize(
        "check_name, field_name, compliant_value, non_compliant_value, expected_phrase",
        PASSWORD_POLICY_CHECK_CASES,
    )
    def test_non_compliant_password_policy_fails(
        self,
        check_name,
        field_name,
        compliant_value,
        non_compliant_value,
        expected_phrase,
    ):
        policy = password_policy(**{field_name: non_compliant_value})
        findings = _run_password_policy_check(
            check_name,
            build_authenticator_client(password_policies={policy.id: policy}),
        )

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert findings[0].resource_id == policy.id
        assert expected_phrase in findings[0].status_extended

    def test_multiple_active_password_policies_emit_one_finding_each(self):
        check_name = "authenticator_password_minimum_length_15"
        compliant = password_policy(policy_id="pol-good", name="Strict", min_length=15)
        weak = password_policy(
            policy_id="pol-weak", name="Weak", min_length=8, priority=2
        )

        findings = _run_password_policy_check(
            check_name,
            build_authenticator_client(
                password_policies={compliant.id: compliant, weak.id: weak}
            ),
        )

        assert len(findings) == 2
        by_name = {finding.resource_name: finding for finding in findings}
        assert by_name["Strict"].status == "PASS"
        assert by_name["Weak"].status == "FAIL"
