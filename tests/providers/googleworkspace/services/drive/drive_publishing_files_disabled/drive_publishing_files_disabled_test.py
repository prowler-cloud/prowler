from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDrivePublishingFilesDisabled:
    def test_pass_publishing_disabled(self):
        """Test PASS when publishing files to web is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled import (
                drive_publishing_files_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_publishing_files=False)

            check = drive_publishing_files_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_publishing_enabled(self):
        """Test FAIL when publishing files to web is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled import (
                drive_publishing_files_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_publishing_files=True)

            check = drive_publishing_files_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) but fetch succeeded"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled import (
                drive_publishing_files_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_publishing_files=None)

            check = drive_publishing_files_disabled()
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
                "prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled import (
                drive_publishing_files_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_publishing_files_disabled()
            findings = check.execute()

            assert len(findings) == 0
