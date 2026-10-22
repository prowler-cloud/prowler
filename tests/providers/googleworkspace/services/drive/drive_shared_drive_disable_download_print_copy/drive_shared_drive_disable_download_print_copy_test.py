from unittest.mock import patch

from prowler.providers.googleworkspace.services.drive.drive_service import DrivePolicies
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDriveSharedDriveDisableDownloadPrintCopy:
    def test_pass_editors_only(self):
        """Test PASS when download/print/copy is restricted to editors only"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy="EDITORS_ONLY"
            )

            check = drive_shared_drive_disable_download_print_copy()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "EDITORS_ONLY" in findings[0].status_extended
            assert findings[0].resource_name == "Drive Policies"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_pass_managers_only(self):
        """Test PASS when download/print/copy is restricted to managers only"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy="MANAGERS_ONLY"
            )

            check = drive_shared_drive_disable_download_print_copy()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "MANAGERS_ONLY" in findings[0].status_extended

    def test_fail_all_allowed(self):
        """Test FAIL when all users (including viewers/commenters) can download/print/copy"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy="ALL"
            )

            check = drive_shared_drive_disable_download_print_copy()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "ALL" in findings[0].status_extended

    def test_pass_using_default(self):
        """Test PASS when no explicit policy is set (None) — Google default is secure"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy=None
            )

            check = drive_shared_drive_disable_download_print_copy()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "secure default" in findings[0].status_extended

    def test_evaluates_the_setting_when_the_service_is_off_for_everyone(self):
        """Existing shares stay reachable when Drive is off, so the stored setting still counts"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_client.provider = mock_provider
            mock_client.policies_fetched = True
            mock_client.policies = DrivePolicies(
                service_state="DISABLED", allowed_parties_for_download_print_copy="ALL"
            )

            findings = drive_shared_drive_disable_download_print_copy().execute()

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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy="ALL"
            )

            findings = drive_shared_drive_disable_download_print_copy().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert findings[0].status_extended == (
                f"Download, print, and copy in shared drives in domain {DOMAIN} is "
                f"set to ALL. These actions should be restricted to editors or "
                f"managers only. This may be expected because shared drive settings "
                f"cannot be changed on the Google Workspace Business Starter edition, "
                f"where new shared drives allow every sharing option."
            )

    def test_fail_on_a_supported_edition_gives_no_excuse(self):
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.editions = ["Business Starter", "Business Standard"]

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = True
            mock_drive_client.policies = DrivePolicies(
                allowed_parties_for_download_print_copy="ALL"
            )

            findings = drive_shared_drive_disable_download_print_copy().execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "This may be expected" not in findings[0].status_extended

    def test_no_resources(self):
        """No policies could be read, so there is nothing to report"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            findings = drive_shared_drive_disable_download_print_copy().execute()

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
                "prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy.drive_client"
            ) as mock_drive_client,
        ):
            from prowler.providers.googleworkspace.services.drive.drive_shared_drive_disable_download_print_copy.drive_shared_drive_disable_download_print_copy import (
                drive_shared_drive_disable_download_print_copy,
            )

            mock_drive_client.provider = mock_provider
            mock_drive_client.policies_fetched = False
            mock_drive_client.policies = DrivePolicies()

            check = drive_shared_drive_disable_download_print_copy()
            findings = check.execute()

            assert len(findings) == 0
