from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveExternalSharingWarnUsers:
    def test_pass_warning_enabled(self):
        """Test PASS when external sharing warning is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users import (
                drive_external_sharing_warn_users,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(warn_for_external_sharing=True)

            check = drive_external_sharing_warn_users()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "enabled" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].resource_id == CUSTOMER_ID
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == mock_provider.domain_resource.dict()

    def test_fail_warning_disabled(self):
        """Test FAIL when external sharing warning is explicitly disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users import (
                drive_external_sharing_warn_users,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(warn_for_external_sharing=False)

            check = drive_external_sharing_warn_users()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "disabled" in findings[0].status_extended

    def test_pass_using_default(self):
        """Test PASS when no explicit policy is set (None) — Google default is secure"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users import (
                drive_external_sharing_warn_users,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(warn_for_external_sharing=None)

            check = drive_external_sharing_warn_users()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_external_sharing_warn_users.drive_external_sharing_warn_users import (
                drive_external_sharing_warn_users,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_external_sharing_warn_users()
            findings = check.execute()

            assert len(findings) == 0
