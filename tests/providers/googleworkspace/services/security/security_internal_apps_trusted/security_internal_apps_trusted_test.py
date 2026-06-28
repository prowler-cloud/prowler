from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityInternalAppsTrusted:
    def test_pass_internal_apps_trusted(self):
        """Test PASS when internal domain-owned apps are trusted"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted import (
                security_internal_apps_trusted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(trust_internal_apps=True)

            check = security_internal_apps_trusted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "trusted" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_none_secure_default(self):
        """Test PASS when internal apps trust is None (secure default)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted import (
                security_internal_apps_trusted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(trust_internal_apps=None)

            check = security_internal_apps_trusted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_internal_apps_not_trusted(self):
        """Test FAIL when internal domain-owned apps are not trusted"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted import (
                security_internal_apps_trusted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(trust_internal_apps=False)

            check = security_internal_apps_trusted()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not trusted" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_internal_apps_trusted.security_internal_apps_trusted import (
                security_internal_apps_trusted,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_internal_apps_trusted()
            findings = check.execute()

            assert len(findings) == 0
