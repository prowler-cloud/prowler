from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveSharedDriveManagersCannotOverride:
    def test_pass_override_disabled(self):
        """Test PASS when managers cannot override shared drive settings"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allow_managers_to_override_settings=False
            )

            check = drive_shared_drive_managers_cannot_override()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "cannot override" in findings[0].status_extended
            assert findings[0].resource_name == "Drive Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_override_allowed(self):
        """Test FAIL when managers can override shared drive settings"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allow_managers_to_override_settings=True
            )

            check = drive_shared_drive_managers_cannot_override()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "allowed to override" in findings[0].status_extended

    def test_fail_no_policy_set(self):
        """Test FAIL when no explicit policy is set (None) but fetch succeeded"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allow_managers_to_override_settings=None
            )

            check = drive_shared_drive_managers_cannot_override()
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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allow_managers_to_override_settings=True
            )

            findings = drive_shared_drive_managers_cannot_override().execute()

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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allow_managers_to_override_settings=True
            )

            findings = drive_shared_drive_managers_cannot_override().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert findings[0].status_extended == (
                f"Shared drive managers in domain {DOMAIN} are allowed to override "
                f"shared drive settings. Managers should not be allowed to override "
                f"shared drive settings. This may be expected because shared drive "
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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            findings = drive_shared_drive_managers_cannot_override().execute()

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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_managers_cannot_override.drive_shared_drive_managers_cannot_override import (
                drive_shared_drive_managers_cannot_override,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_shared_drive_managers_cannot_override()
            findings = check.execute()

            assert len(findings) == 0
