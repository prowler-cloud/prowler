from unittest.mock import patch

from prowler.providers.googleworkspace.services.security.security_service import (
    SecurityPolicies,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    set_mocked_googleworkspace_provider,
)


class TestSecurityDlpDriveRulesConfigured:
    def test_pass_dlp_rules_configured(self):
        """Test PASS when DLP policies for Google Drive are configured"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured import (
                security_dlp_drive_rules_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(dlp_drive_rules_exist=True)

            check = security_dlp_drive_rules_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "configured" in findings[0].status_extended
            assert findings[0].resource_name == "Security Policies"
            assert findings[0].resource_id == "securityPolicies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_no_dlp_rules(self):
        """Test FAIL when no DLP policies for Google Drive are configured"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured import (
                security_dlp_drive_rules_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(dlp_drive_rules_exist=False)

            check = security_dlp_drive_rules_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "No active" in findings[0].status_extended

    def test_fail_none_no_dlp_rules(self):
        """Test FAIL when DLP rules existence is None (no active rules)"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured import (
                security_dlp_drive_rules_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = SecurityPolicies(dlp_drive_rules_exist=None)

            check = security_dlp_drive_rules_configured()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "No active" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured.security_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.security.security_dlp_drive_rules_configured.security_dlp_drive_rules_configured import (
                security_dlp_drive_rules_configured,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = False
            mock_client.policies = SecurityPolicies()

            check = security_dlp_drive_rules_configured()
            findings = check.execute()

            assert len(findings) == 0
