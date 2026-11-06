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
            assert findings[0].resource_name == "Drive Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_when_external_sharing_is_limited_to_allowlisted_domains(self):
        """The publishing flag only applies when sharing outside the organization is ON.

        Under "Allowlisted domains" the Admin console hides the option and
        nothing can be made visible to anyone with the link, whatever value
        the API still stores for the flag.
        """
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
            mock_drive_client.policies = DrivePolicies(
                external_sharing_mode="ALLOWLISTED_DOMAINS",
                allow_publishing_files=True,
            )

            findings = drive_publishing_files_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Publishing files to the web is not possible in domain {DOMAIN}: "
                f"sharing outside of the organization is limited to allowlisted "
                f"domains."
            )

    def test_pass_when_external_sharing_is_off(self):
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
            mock_drive_client.policies = DrivePolicies(
                external_sharing_mode="DISALLOWED",
                allow_publishing_files=None,
            )

            findings = drive_publishing_files_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Publishing files to the web is not possible in domain {DOMAIN}: "
                f"sharing outside of the organization is off."
            )

    def test_fail_when_external_sharing_is_on_and_publishing_is_allowed(self):
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
            mock_drive_client.policies = DrivePolicies(
                external_sharing_mode="ALLOWED",
                allow_publishing_files=True,
            )

            findings = drive_publishing_files_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "enabled" in findings[0].status_extended

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

    def test_evaluates_the_setting_when_the_service_is_off_for_everyone(self):
        """Existing shares stay reachable when Drive is off, so the stored setting still counts"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_publishing_files_disabled.drive_publishing_files_disabled import (
                drive_publishing_files_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allow_publishing_files=True
            )

            findings = drive_publishing_files_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "turned off" not in findings[0].status_extended

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
