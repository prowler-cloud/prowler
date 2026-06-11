from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurity2svHardwareKeysAdmins:
    def test_pass_passkey_only(self):
        """Test PASS when 2SV enforcement requires security keys only"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins import (
                security_2sv_hardware_keys_admins,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                two_sv_allowed_factor_set="PASSKEY_ONLY"
            )

            check = security_2sv_hardware_keys_admins()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "security keys only" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_all_methods_allowed(self):
        """Test FAIL when 2SV enforcement allows ALL methods"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins import (
                security_2sv_hardware_keys_admins,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(two_sv_allowed_factor_set="ALL")

            check = security_2sv_hardware_keys_admins()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ALL" in findings[0].status_extended

    def test_fail_none_not_configured(self):
        """Test FAIL when 2SV enforcement factor is not configured (None)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins import (
                security_2sv_hardware_keys_admins,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(two_sv_allowed_factor_set=None)

            check = security_2sv_hardware_keys_admins()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_hardware_keys_admins.security_2sv_hardware_keys_admins import (
                security_2sv_hardware_keys_admins,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_2sv_hardware_keys_admins()
            findings = check.execute()

            assert len(findings) == 0
