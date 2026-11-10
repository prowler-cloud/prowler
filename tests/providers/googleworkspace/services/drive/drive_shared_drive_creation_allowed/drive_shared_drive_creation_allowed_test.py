from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveSharedDriveCreationAllowed:
    def test_pass_creation_allowed(self):
        """Test PASS when users are allowed to create shared drives"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed import (
                drive_shared_drive_creation_allowed,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_shared_drive_creation=True)

            check = drive_shared_drive_creation_allowed()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "allowed" in findings[0].status_extended
            assert findings[0].resource_name == "Drive Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_creation_disabled(self):
        """Test FAIL when users are prevented from creating shared drives"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed import (
                drive_shared_drive_creation_allowed,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allow_shared_drive_creation=False
            )

            check = drive_shared_drive_creation_allowed()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "prevented" in findings[0].status_extended

    def test_pass_using_default(self):
        """Test PASS when no explicit policy is set (None) — Google default is secure"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed import (
                drive_shared_drive_creation_allowed,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(allow_shared_drive_creation=None)

            check = drive_shared_drive_creation_allowed()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended

    def test_pass_when_the_service_is_off_for_everyone(self):
        """A setting that only acts while the service is on has no effect once the service is off"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed import (
                drive_shared_drive_creation_allowed,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allow_shared_drive_creation=False
            )

            findings = drive_shared_drive_creation_allowed().execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert findings[0].status_extended == (
                f"Google Drive is turned off for everyone in domain {DOMAIN}, "
                f"so no shared drive can be created."
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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_creation_allowed.drive_shared_drive_creation_allowed import (
                drive_shared_drive_creation_allowed,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_shared_drive_creation_allowed()
            findings = check.execute()

            assert len(findings) == 0
