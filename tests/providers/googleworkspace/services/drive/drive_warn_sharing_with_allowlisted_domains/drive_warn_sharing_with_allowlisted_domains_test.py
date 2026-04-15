from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveWarnSharingWithAllowlistedDomains:
    def test_pass_warning_enabled(self):
        """Test PASS when warning for sharing with allowlisted domains is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains import (
                drive_warn_sharing_with_allowlisted_domains,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                warn_for_sharing_outside_allowlisted_domains=True
            )

            check = drive_warn_sharing_with_allowlisted_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "warned" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_warning_disabled(self):
        """Test FAIL when warning for sharing with allowlisted domains is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains import (
                drive_warn_sharing_with_allowlisted_domains,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                warn_for_sharing_outside_allowlisted_domains=False
            )

            check = drive_warn_sharing_with_allowlisted_domains()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "disabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) but fetch succeeded"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains import (
                drive_warn_sharing_with_allowlisted_domains,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                warn_for_sharing_outside_allowlisted_domains=None
            )

            check = drive_warn_sharing_with_allowlisted_domains()
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
                "prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_warn_sharing_with_allowlisted_domains.drive_warn_sharing_with_allowlisted_domains import (
                drive_warn_sharing_with_allowlisted_domains,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_warn_sharing_with_allowlisted_domains()
            findings = check.execute()

            assert len(findings) == 0
