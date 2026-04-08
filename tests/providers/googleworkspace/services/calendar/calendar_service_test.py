from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestCalendarService:
    def test_calendar_fetch_policies_all_settings(self):
        """Test fetching all 3 calendar policy settings from Cloud Identity API"""
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
                        "type": "settings/calendar.primary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/calendar.secondary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"
                        },
                    }
                },
                {
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnInvite": True},
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
                "prowler.providers.googleworkspace.services.calendar.calendar_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_service import (
                Calendar,
            )

            calendar = Calendar(mock_provider)

            assert calendar.policies_fetched is True
            assert (
                calendar.policies.primary_calendar_external_sharing
                == "EXTERNAL_FREE_BUSY_ONLY"
            )
            assert (
                calendar.policies.secondary_calendar_external_sharing
                == "EXTERNAL_ALL_INFO_READ_ONLY"
            )
            assert calendar.policies.external_invitations_warning is True

    def test_calendar_fetch_policies_empty_response(self):
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
                "prowler.providers.googleworkspace.services.calendar.calendar_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_service import (
                Calendar,
            )

            calendar = Calendar(mock_provider)

            assert calendar.policies_fetched is True
            assert calendar.policies.primary_calendar_external_sharing is None
            assert calendar.policies.secondary_calendar_external_sharing is None
            assert calendar.policies.external_invitations_warning is None

    def test_calendar_fetch_policies_api_error(self):
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
                "prowler.providers.googleworkspace.services.calendar.calendar_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_service import (
                Calendar,
            )

            calendar = Calendar(mock_provider)

            assert calendar.policies_fetched is False
            assert calendar.policies.primary_calendar_external_sharing is None
            assert calendar.policies.secondary_calendar_external_sharing is None
            assert calendar.policies.external_invitations_warning is None

    def test_calendar_fetch_policies_build_service_returns_none(self):
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
                "prowler.providers.googleworkspace.services.calendar.calendar_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_service import (
                Calendar,
            )

            calendar = Calendar(mock_provider)

            assert calendar.policies_fetched is False
            assert calendar.policies.primary_calendar_external_sharing is None
            assert calendar.policies.secondary_calendar_external_sharing is None
            assert calendar.policies.external_invitations_warning is None

    def test_calendar_fetch_policies_execute_raises(self):
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
                "prowler.providers.googleworkspace.services.calendar.calendar_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.calendar.calendar_service import (
                Calendar,
            )

            calendar = Calendar(mock_provider)

            assert calendar.policies_fetched is False
            assert calendar.policies.primary_calendar_external_sharing is None
            assert calendar.policies.secondary_calendar_external_sharing is None
            assert calendar.policies.external_invitations_warning is None

    def test_calendar_policies_model(self):
        """Test CalendarPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.calendar.calendar_service import (
            CalendarPolicies,
        )

        policies = CalendarPolicies(
            primary_calendar_external_sharing="EXTERNAL_FREE_BUSY_ONLY",
            secondary_calendar_external_sharing="EXTERNAL_ALL_INFO_READ_WRITE",
            external_invitations_warning=True,
        )

        assert policies.primary_calendar_external_sharing == "EXTERNAL_FREE_BUSY_ONLY"
        assert (
            policies.secondary_calendar_external_sharing
            == "EXTERNAL_ALL_INFO_READ_WRITE"
        )
        assert policies.external_invitations_warning is True
