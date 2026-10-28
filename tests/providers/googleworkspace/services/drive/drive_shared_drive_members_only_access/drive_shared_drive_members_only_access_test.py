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
            assert findings[0].resource_name == "Drive Policies"
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

    def test_evaluates_the_setting_when_the_service_is_off_for_everyone(self):
        """Existing shares stay reachable when Drive is off, so the stored setting still counts"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_members_only_access.drive_shared_drive_members_only_access import (
                drive_shared_drive_members_only_access,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allow_non_member_access=True
            )

            findings = drive_shared_drive_members_only_access().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "turned off" not in findings[0].status_extended

    def test_fail_on_business_starter_says_the_setting_cannot_be_changed(self):
        """Google keeps every shared drive setting allowed on Business Starter; the finding names the edition"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.editions = ["Business Starter"]

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

            findings = drive_shared_drive_members_only_access().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert findings[0].status_extended == (
                f"Shared drive file access in domain {DOMAIN} allows non-members to "
                f"be added to files. Shared drive file access should be restricted "
                f"to members only. This may be expected because shared drive "
                f"settings cannot be changed on the Google Workspace Business Starter "
                f"edition, where new shared drives allow every sharing option."
            )

    def test_no_resources(self):
        """No policies could be read, so there is nothing to report"""
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

            findings = drive_shared_drive_members_only_access().execute()

            assert len(findings) == 0

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
