from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecuritySuperAdminRecoveryDisabled:
    def test_pass_recovery_disabled(self):
        """Test PASS when Super Admin account recovery is explicitly disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled import (
                security_super_admin_recovery_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(super_admin_recovery_enabled=False)

            check = security_super_admin_recovery_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_none_secure_default(self):
        """Test PASS when Super Admin account recovery is None (secure default)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled import (
                security_super_admin_recovery_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(super_admin_recovery_enabled=None)

            check = security_super_admin_recovery_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_recovery_enabled(self):
        """Test FAIL when Super Admin account recovery is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled import (
                security_super_admin_recovery_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(super_admin_recovery_enabled=True)

            check = security_super_admin_recovery_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_super_admin_recovery_disabled.security_super_admin_recovery_disabled import (
                security_super_admin_recovery_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_super_admin_recovery_disabled()
            findings = check.execute()

            assert len(findings) == 0
