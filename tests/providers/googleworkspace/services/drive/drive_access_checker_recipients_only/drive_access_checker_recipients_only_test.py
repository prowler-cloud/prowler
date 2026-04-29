from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveAccessCheckerRecipientsOnly:
    def test_pass_recipients_only(self):
        """Test PASS when Access Checker is set to recipients only"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only import (
                drive_access_checker_recipients_only,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                access_checker_suggestions="RECIPIENTS_ONLY"
            )

            check = drive_access_checker_recipients_only()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "recipients only" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_recipients_or_audience(self):
        """Test FAIL when Access Checker allows audience suggestions"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only import (
                drive_access_checker_recipients_only,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                access_checker_suggestions="RECIPIENTS_OR_AUDIENCE"
            )

            check = drive_access_checker_recipients_only()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "RECIPIENTS_OR_AUDIENCE" in findings[0].status_extended

    def test_fail_recipients_or_audience_or_public(self):
        """Test FAIL when Access Checker allows public suggestions"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only import (
                drive_access_checker_recipients_only,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                access_checker_suggestions="RECIPIENTS_OR_AUDIENCE_OR_PUBLIC"
            )

            check = drive_access_checker_recipients_only()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) but fetch succeeded"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only import (
                drive_access_checker_recipients_only,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(access_checker_suggestions=None)

            check = drive_access_checker_recipients_only()
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
                "prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_access_checker_recipients_only.drive_access_checker_recipients_only import (
                drive_access_checker_recipients_only,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_access_checker_recipients_only()
            findings = check.execute()

            assert len(findings) == 0
