from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurity2svEnforced:
    def test_pass_2sv_enforced(self):
        """Test PASS when 2-Step Verification enforcement is active"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced import (
                security_2sv_enforced,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(
                two_sv_enforced_from="2026-05-25T15:27:52.352Z"
            )

            check = security_2sv_enforced()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "active" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_none_not_configured(self):
        """Test FAIL when 2-Step Verification enforcement is not configured (None)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced import (
                security_2sv_enforced,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(two_sv_enforced_from=None)

            check = security_2sv_enforced()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not configured" in findings[0].status_extended

    def test_fail_empty_off(self):
        """Test FAIL when 2-Step Verification enforcement is set to OFF (empty string)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced import (
                security_2sv_enforced,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(two_sv_enforced_from="")

            check = security_2sv_enforced()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "OFF" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_2sv_enforced.security_2sv_enforced import (
                security_2sv_enforced,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_2sv_enforced()
            findings = check.execute()

            assert len(findings) == 0
