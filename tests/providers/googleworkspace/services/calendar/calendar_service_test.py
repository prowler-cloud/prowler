from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    ROOT_ORG_UNIT_ID,
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

    def test_the_admin_policy_outranks_a_system_default_returned_after_it(self):
        """The greatest sortOrder is the value in force, whatever order the API lists them in"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "type": "ADMIN",
                    "policyQuery": {"sortOrder": 201.00131},
                    "setting": {
                        "type": "settings/calendar.secondary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"
                        },
                    },
                },
                {
                    "type": "SYSTEM",
                    "policyQuery": {"sortOrder": 100.00004},
                    "setting": {
                        "type": "settings/calendar.secondary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"
                        },
                    },
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
                calendar.policies.secondary_calendar_external_sharing
                == "EXTERNAL_FREE_BUSY_ONLY"
            )

    def test_off_for_everyone_when_off_at_the_root_with_no_override(self):
        """A root-level DISABLED status with no org unit or group override is off for everyone"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "type": "ADMIN",
                    "policyQuery": {
                        "orgUnit": f"orgUnits/{ROOT_ORG_UNIT_ID}",
                        "sortOrder": 201.00122,
                    },
                    "setting": {
                        "type": "settings/calendar.service_status",
                        "value": {"serviceState": "DISABLED"},
                    },
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

            fetched = Calendar(mock_provider)

            assert fetched.policies_fetched is True
            assert fetched.policies.service_state == "DISABLED"
            assert fetched.policies.service_state_overridden is False
            assert fetched.policies.off_for_everyone is True

    def test_reads_the_service_status_and_its_overrides(self):
        """Off at the customer level only counts when no org unit or group turns the service back on"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "type": "ADMIN",
                    "policyQuery": {"sortOrder": 201.00122},
                    "setting": {
                        "type": "settings/calendar.service_status",
                        "value": {"serviceState": "DISABLED"},
                    },
                },
                {
                    "type": "ADMIN",
                    "policyQuery": {"orgUnit": "orgUnits/sub", "sortOrder": 301.00122},
                    "setting": {
                        "type": "settings/calendar.service_status",
                        "value": {"serviceState": "ENABLED"},
                    },
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

            fetched = Calendar(mock_provider)

            assert fetched.policies_fetched is True
            assert fetched.policies.service_state == "DISABLED"
            assert fetched.policies.service_state_overridden is True
            assert fetched.policies.off_for_everyone is False

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

    def test_calendar_fetch_policies_ignores_ou_and_group_level(self):
        """Test that OU-level and group-level policies are skipped, only customer-level used"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        # Response includes policies at different org levels:
        # customer-level (no policyQuery), OU-level, and group-level
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    # Customer-level: no policyQuery → should be used
                    "setting": {
                        "type": "settings/calendar.primary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"
                        },
                    }
                },
                {
                    # OU-level: has policyQuery.orgUnit → should be skipped
                    "policyQuery": {"orgUnit": "orgUnits/sales_team"},
                    "setting": {
                        "type": "settings/calendar.primary_calendar_max_allowed_external_sharing",
                        "value": {
                            "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE"
                        },
                    },
                },
                {
                    # Group-level: has policyQuery.group → should be skipped
                    "policyQuery": {"group": "groups/contractors"},
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnInvite": False},
                    },
                },
                {
                    # Customer-level: no policyQuery → should be used
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
            # Customer-level values should be stored
            assert (
                calendar.policies.primary_calendar_external_sharing
                == "EXTERNAL_FREE_BUSY_ONLY"
            )
            assert calendar.policies.external_invitations_warning is True
            # OU-level value (EXTERNAL_ALL_INFO_READ_WRITE) should NOT have overwritten
            # Group-level value (warnOnInvite: False) should NOT have overwritten

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
