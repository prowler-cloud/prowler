from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveDesktopAccessDisabled:
    def test_pass_desktop_disabled(self):
        """Test PASS when Drive for desktop is disabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled import (
                drive_desktop_access_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_drive_for_desktop=False)

            check = drive_desktop_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "disabled" in findings[0].status_extended
            assert findings[0].resource_name == "Drive Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_desktop_enabled(self):
        """Test FAIL when Drive for desktop is enabled"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled import (
                drive_desktop_access_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_drive_for_desktop=True)

            check = drive_desktop_access_disabled()
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
                "prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled import (
                drive_desktop_access_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_drive_for_desktop=None)

            check = drive_desktop_access_disabled()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "not explicitly configured" in findings[0].status_extended

    def test_pass_when_the_service_is_off_for_everyone(self):
        """A setting that only acts while the service is on has no effect once the service is off"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled import (
                drive_desktop_access_disabled,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allow_drive_for_desktop=True
            )

            findings = drive_desktop_access_disabled().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Google Drive is turned off for everyone in domain {DOMAIN}, "
                f"so Drive for desktop cannot sync any content."
            )

    def test_no_findings_when_fetch_failed(self):
        """Test no findings returned when the API fetch failed"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_desktop_access_disabled.drive_desktop_access_disabled import (
                drive_desktop_access_disabled,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_desktop_access_disabled()
            findings = check.execute()

            assert len(findings) == 0
