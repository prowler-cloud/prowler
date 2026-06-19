from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityAppAccessRestricted:
    def test_pass_access_restricted(self):
        """Test PASS when application access to Google services is restricted"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted import (
                security_app_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(google_services_restricted=True)

            check = security_app_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "restricted" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_access_unrestricted(self):
        """Test FAIL when application access to Google services is unrestricted"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted import (
                security_app_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(google_services_restricted=False)

            check = security_app_access_restricted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "unrestricted" in findings[0].status_extended

    def test_fail_none_not_configured(self):
        """Test FAIL when application access is not configured (None)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted import (
                security_app_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(google_services_restricted=None)

            check = security_app_access_restricted()
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
                "prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_app_access_restricted.security_app_access_restricted import (
                security_app_access_restricted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_app_access_restricted()
            findings = check.execute()

            assert len(findings) == 0
