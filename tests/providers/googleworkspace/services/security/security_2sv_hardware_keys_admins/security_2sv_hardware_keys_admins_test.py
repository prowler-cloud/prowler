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
    "security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins."
    "security_client"
)

# A domain that satisfies every step of the CIS audit procedure.
COMPLIANT = dict(
    two_sv_allowed_factor_set="PASSKEY_ONLY",
    two_sv_enforced_from="2026-05-25T15:27:52.352Z",
    two_sv_allow_enrollment=True,
    two_sv_backup_code_exception_period="86400s",
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
        from prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins import (
            security_2sv_hardware_keys_admins,
        )

        mock_client.provider = mock_provider
        mock_client.policies_fetched = policies_fetched
        mock_client.policies = SecurityPolicies(**overrides)

        return security_2sv_hardware_keys_admins().execute()


class TestSecurity2svHardwareKeysAdmins:
    def test_pass_full_audit_procedure_met(self):
        """PASS when every step of the CIS audit procedure is satisfied"""
        findings = run_check(**COMPLIANT)

        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "requires security keys only" in findings[0].status_extended
        assert findings[0].resource_name == "Security Policies"
        assert findings[0].resource_id == "securityPolicies"
        assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_no_suspension_grace_period(self):
        """PASS with no suspension grace period, which is stricter than 1 day"""
        findings = run_check(
            **{**COMPLIANT, "two_sv_backup_code_exception_period": "0s"}
        )

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_pass_ignores_new_user_enrollment_period(self):
        """The new user enrollment period belongs to 4.1.1.1 and 4.1.1.3, not here"""
        findings = run_check(
            **{**COMPLIANT, "two_sv_enrollment_grace_period": "2592000s"}
        )

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_pass_ignores_advanced_protection_security_codes(self):
        """The Advanced Protection Program page is covered by CIS 4.1.3.1, not here"""
        findings = run_check(
            **{
                **COMPLIANT,
                "advanced_protection_security_code_option": "ALLOWED_WITHOUT_REMOTE_ACCESS",
            }
        )

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    @pytest.mark.parametrize(
        "overrides, expected",
        [
            ({"two_sv_allowed_factor_set": "ALL"}, "accepted method is ALL"),
            (
                {"two_sv_allowed_factor_set": None},
                "accepted method is not configured",
            ),
            ({"two_sv_enforced_from": None}, "enforcement is not configured"),
            (
                {"two_sv_enforced_from": "1970-01-01T00:00:00Z"},
                "enforcement is set to OFF",
            ),
            ({"two_sv_allow_enrollment": False}, "not allowed to turn on"),
            (
                {"two_sv_enforced_from": "2099-01-01T00:00:00Z"},
                "enforcement does not start until 2099-01-01T00:00:00Z",
            ),
            (
                {"two_sv_backup_code_exception_period": "1209600s"},
                "suspension grace period is 14 day(s)",
            ),
            (
                {"two_sv_backup_code_exception_period": "7d"},
                "suspension grace period '7d' could not be read",
            ),
        ],
    )
    def test_fail_each_audit_step(self, overrides, expected):
        """FAIL when any single step of the CIS audit procedure is not met"""
        findings = run_check(**{**COMPLIANT, **overrides})

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert expected in findings[0].status_extended

    def test_fail_keeps_domain_wide_scope_note(self):
        """The domain-wide scope caveat is reported on failure too"""
        findings = run_check()

        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "role-specific 2SV enforcement" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """No findings returned when the API fetch failed"""
        assert run_check(policies_fetched=False) == []
