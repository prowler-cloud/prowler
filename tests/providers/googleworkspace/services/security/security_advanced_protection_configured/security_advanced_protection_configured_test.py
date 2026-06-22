from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityAdvancedProtectionConfigured:
    def test_pass_properly_configured(self):
        """Test PASS when Advanced Protection is configured with enrollment and codes blocked"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured import (
                security_advanced_protection_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                advanced_protection_enrollment=True,
                advanced_protection_security_code_option="CODES_NOT_ALLOWED",
            )

            check = security_advanced_protection_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "configured" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_codes_allowed(self):
        """Test FAIL when enrollment is enabled but security codes are allowed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured import (
                security_advanced_protection_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                advanced_protection_enrollment=True,
                advanced_protection_security_code_option="ALLOWED_WITHOUT_REMOTE_ACCESS",
            )

            check = security_advanced_protection_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not properly configured" in findings[0].status_extended

    def test_fail_enrollment_disabled(self):
        """Test FAIL when enrollment is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured import (
                security_advanced_protection_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                advanced_protection_enrollment=False,
            )

            check = security_advanced_protection_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not properly configured" in findings[0].status_extended

    def test_fail_enrollment_unset(self):
        """Test FAIL when enrollment is None (not configured)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured import (
                security_advanced_protection_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                advanced_protection_enrollment=None,
                advanced_protection_security_code_option="CODES_NOT_ALLOWED",
            )

            check = security_advanced_protection_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enrollment is not configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_advanced_protection_configured.security_advanced_protection_configured import (
                security_advanced_protection_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_advanced_protection_configured()
            findings = check.execute()

            assert len(findings) == 0
