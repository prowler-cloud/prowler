from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityPasswordPolicyStrong:
    def test_pass_strong_password_policy(self):
        """Test PASS when password policy meets CIS requirements"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong import (
                security_password_policy_strong,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                password_minimum_length=14,
                password_allowed_strength="STRONG",
                password_allow_reuse=False,
                password_enforce_at_login=True,
                password_expiration_duration="31536000s",
            )

            check = security_password_policy_strong()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "meets CIS requirements" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_weak_password_policy(self):
        """Test FAIL when password policy does not meet CIS requirements"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong import (
                security_password_policy_strong,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                password_minimum_length=8,
                password_allowed_strength="STRONG",
                password_allow_reuse=False,
                password_enforce_at_login=False,
                password_expiration_duration="0s",
            )

            check = security_password_policy_strong()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "does not meet" in findings[0].status_extended

    def test_fail_none_all_defaults(self):
        """Test FAIL when all password policy fields are None (defaults)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong import (
                security_password_policy_strong,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                password_minimum_length=None,
                password_allowed_strength=None,
                password_allow_reuse=None,
                password_enforce_at_login=None,
                password_expiration_duration=None,
            )

            check = security_password_policy_strong()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "does not meet" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_password_policy_strong.security_password_policy_strong import (
                security_password_policy_strong,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_password_policy_strong()
            findings = check.execute()

            assert len(findings) == 0
