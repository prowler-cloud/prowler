from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestDriveService:
    def test_drive_fetch_policies_all_settings(self):
        """Test fetching all 3 Drive and Docs policy settings from Cloud Identity API"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        # Mock the actual Cloud Identity Policy API v1 response shape:
        # - "type" (not "name"), prefixed with "settings/"
        # - inner value field names are camelCase
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/drive_and_docs.external_sharing",
                        "value": {
                            "externalSharingMode": "ALLOWLISTED_DOMAINS",
                            "warnForExternalSharing": True,
                            "warnForSharingOutsideAllowlistedDomains": True,
                            "allowPublishingFiles": False,
                            "accessCheckerSuggestions": "RECIPIENTS_ONLY",
                            "allowedPartiesForDistributingContent": "ELIGIBLE_INTERNAL_USERS",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/drive_and_docs.shared_drive_creation",
                        "value": {
                            "allowSharedDriveCreation": True,
                            "allowManagersToOverrideSettings": False,
                            "allowNonMemberAccess": False,
                            "allowedPartiesForDownloadPrintCopy": "EDITORS_ONLY",
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/drive_and_docs.drive_for_desktop",
                        "value": {"allowDriveForDesktop": False},
                    }
                },
            ]
        }
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.drive.drive_service import (
                Drive,
            )

            drive = Drive(mock_provider)

            assert drive.policies_fetched is True
            assert drive.policies.external_sharing_mode == "ALLOWLISTED_DOMAINS"
            assert drive.policies.warn_for_external_sharing is True
            assert drive.policies.warn_for_sharing_outside_allowlisted_domains is True
            assert drive.policies.allow_publishing_files is False
            assert drive.policies.access_checker_suggestions == "RECIPIENTS_ONLY"
            assert (
                drive.policies.allowed_parties_for_distributing_content
                == "ELIGIBLE_INTERNAL_USERS"
            )
            assert drive.policies.allow_shared_drive_creation is True
            assert drive.policies.allow_managers_to_override_settings is False
            assert drive.policies.allow_non_member_access is False
            assert (
                drive.policies.allowed_parties_for_download_print_copy == "EDITORS_ONLY"
            )
            assert drive.policies.allow_drive_for_desktop is False

    def test_drive_fetch_policies_empty_response(self):
        """Test handling empty policies response"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {"policies": []}
        mock_service.policies().list.return_value = mock_policies_list
        mock_service.policies().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.drive.drive_service import (
                Drive,
            )

            drive = Drive(mock_provider)

            assert drive.policies_fetched is True
            assert drive.policies.external_sharing_mode is None
            assert drive.policies.warn_for_external_sharing is None
            assert drive.policies.allow_publishing_files is None
            assert drive.policies.allow_shared_drive_creation is None
            assert drive.policies.allow_drive_for_desktop is None

    def test_drive_fetch_policies_api_error(self):
        """Test handling of API errors during policy fetch"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_service.policies().list.side_effect = Exception("API Error")

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.drive.drive_service import (
                Drive,
            )

            drive = Drive(mock_provider)

            assert drive.policies_fetched is False
            assert drive.policies.external_sharing_mode is None
            assert drive.policies.allow_shared_drive_creation is None
            assert drive.policies.allow_drive_for_desktop is None

    def test_drive_fetch_policies_build_service_returns_none(self):
        """Test early return when _build_service fails to construct the client"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.drive.drive_service import (
                Drive,
            )

            drive = Drive(mock_provider)

            assert drive.policies_fetched is False
            assert drive.policies.external_sharing_mode is None
            assert drive.policies.allow_shared_drive_creation is None
            assert drive.policies.allow_drive_for_desktop is None

    def test_drive_fetch_policies_execute_raises(self):
        """Test inner except handler when request.execute() raises during pagination"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_request = MagicMock()
        mock_request.execute.side_effect = Exception("Execute failed")
        mock_service.policies().list.return_value = mock_request

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.drive.drive_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.drive.drive_service import (
                Drive,
            )

            drive = Drive(mock_provider)

            assert drive.policies_fetched is False
            assert drive.policies.external_sharing_mode is None
            assert drive.policies.allow_shared_drive_creation is None
            assert drive.policies.allow_drive_for_desktop is None

    def test_drive_policies_model(self):
        """Test DrivePolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.drive.drive_service import (
            DrivePolicies,
        )

        policies = DrivePolicies(
            external_sharing_mode="ALLOWLISTED_DOMAINS",
            warn_for_external_sharing=True,
            warn_for_sharing_outside_allowlisted_domains=True,
            allow_publishing_files=False,
            access_checker_suggestions="RECIPIENTS_ONLY",
            allowed_parties_for_distributing_content="ELIGIBLE_INTERNAL_USERS",
            allow_shared_drive_creation=True,
            allow_managers_to_override_settings=False,
            allow_non_member_access=False,
            allowed_parties_for_download_print_copy="EDITORS_ONLY",
            allow_drive_for_desktop=False,
        )

        assert policies.external_sharing_mode == "ALLOWLISTED_DOMAINS"
        assert policies.warn_for_external_sharing is True
        assert policies.allow_publishing_files is False
        assert policies.access_checker_suggestions == "RECIPIENTS_ONLY"
        assert policies.allow_shared_drive_creation is True
        assert policies.allow_managers_to_override_settings is False
        assert policies.allow_non_member_access is False
        assert policies.allowed_parties_for_download_print_copy == "EDITORS_ONLY"
        assert policies.allow_drive_for_desktop is False
