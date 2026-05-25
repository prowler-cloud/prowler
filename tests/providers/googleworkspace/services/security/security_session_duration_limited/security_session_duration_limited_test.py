from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecuritySessionDurationLimited:
    def test_pass_session_12_hours(self):
        """Test PASS when session duration is set to 12 hours"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="43200s")

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "12 hours" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_long_session_duration(self):
        """Test FAIL when session duration is too long (336 hours)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration="1209600s")

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "336 hours" in findings[0].status_extended

    def test_fail_none_not_configured(self):
        """Test FAIL when session duration is not explicitly configured (None)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(web_session_duration=None)

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_session_duration_limited.security_session_duration_limited import (
                security_session_duration_limited,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_session_duration_limited()
            findings = check.execute()

            assert len(findings) == 0
