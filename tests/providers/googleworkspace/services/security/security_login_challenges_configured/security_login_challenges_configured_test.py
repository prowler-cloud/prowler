from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityLoginChallengesConfigured:
    def test_pass_employee_id_challenge_disabled(self):
        """Test PASS when employee ID login challenge is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured import (
                security_login_challenges_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(login_challenge_employee_id=False)

            check = security_login_challenges_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_none_secure_default(self):
        """Test PASS when employee ID login challenge is None (secure default)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured import (
                security_login_challenges_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(login_challenge_employee_id=None)

            check = security_login_challenges_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_employee_id_challenge_enabled(self):
        """Test FAIL when employee ID login challenge is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured import (
                security_login_challenges_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(login_challenge_employee_id=True)

            check = security_login_challenges_configured()
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
                "prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_login_challenges_configured.security_login_challenges_configured import (
                security_login_challenges_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_login_challenges_configured()
            findings = check.execute()

            assert len(findings) == 0
