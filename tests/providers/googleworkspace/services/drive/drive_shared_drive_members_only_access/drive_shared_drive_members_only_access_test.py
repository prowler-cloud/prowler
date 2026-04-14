from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveSharedDriveMembersOnlyAccess:
    def test_pass_non_member_access_disabled(self):
        """Test PASS when non-member access to shared drive files is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access import (
                drive_shared_drive_members_only_access,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_non_member_access=False)

            check = drive_shared_drive_members_only_access()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "members only" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_non_member_access_enabled(self):
        """Test FAIL when non-members can be added to shared drive files"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access import (
                drive_shared_drive_members_only_access,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_non_member_access=True)

            check = drive_shared_drive_members_only_access()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "non-members" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) but fetch succeeded"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access import (
                drive_shared_drive_members_only_access,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_non_member_access=None)

            check = drive_shared_drive_members_only_access()
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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access import (
                drive_shared_drive_members_only_access,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_shared_drive_members_only_access()
            findings = check.execute()

            assert len(findings) == 0
