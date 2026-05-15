from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    set_mocked_googleworkspace_provider,
)


class TestGroupsService:
    def test_fetch_policies_all_settings(self):
        """Test fetching all Groups for Business policy settings from Cloud Identity API"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_policies_list = MagicMock()
        mock_policies_list.execute.return_value = {
            "policies": [
                {
                    "setting": {
                        "type": "settings/groups_for_business.groups_sharing",
                        "value": {
                            "collaborationCapability": "DOMAIN_USERS_ONLY",
                            "createGroupsAccessLevel": "ADMIN_ONLY",
                            "ownersCanAllowExternalMembers": False,
                            "ownersCanAllowIncomingMailFromPublic": False,
                            "viewTopicsDefaultAccessLevel": "GROUP_MEMBERS",
                            "ownersCanHideGroups": False,
                            "newGroupsAreHidden": False,
                        },
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is True
            assert groups.policies.collaboration_capability == "DOMAIN_USERS_ONLY"
            assert groups.policies.create_groups_access_level == "ADMIN_ONLY"
            assert groups.policies.owners_can_allow_external_members is False
            assert groups.policies.owners_can_allow_incoming_mail_from_public is False
            assert groups.policies.view_topics_default_access_level == "GROUP_MEMBERS"
            assert groups.policies.owners_can_hide_groups is False
            assert groups.policies.new_groups_are_hidden is False

    def test_fetch_policies_empty_response(self):
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is True
            assert groups.policies.collaboration_capability is None
            assert groups.policies.create_groups_access_level is None
            assert groups.policies.owners_can_allow_external_members is None
            assert groups.policies.owners_can_allow_incoming_mail_from_public is None
            assert groups.policies.view_topics_default_access_level is None

    def test_fetch_policies_api_error(self):
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is False
            assert groups.policies.collaboration_capability is None

    def test_fetch_policies_build_service_returns_none(self):
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=None,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is False
            assert groups.policies.collaboration_capability is None

    def test_fetch_policies_execute_raises(self):
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is False
            assert groups.policies.collaboration_capability is None

    def test_fetch_policies_ignores_ou_and_group_level(self):
        """Test that OU-level and group-level policies are skipped, only customer-level used"""
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
                    # Customer-level: no policyQuery → should be used
                    "setting": {
                        "type": "settings/groups_for_business.groups_sharing",
                        "value": {
                            "collaborationCapability": "DOMAIN_USERS_ONLY",
                            "createGroupsAccessLevel": "ADMIN_ONLY",
                        },
                    }
                },
                {
                    # OU-level: has policyQuery.orgUnit → should be skipped
                    "policyQuery": {"orgUnit": "orgUnits/sales_team"},
                    "setting": {
                        "type": "settings/groups_for_business.groups_sharing",
                        "value": {
                            "collaborationCapability": "ANYONE_CAN_ACCESS",
                        },
                    },
                },
                {
                    # Group-level: has policyQuery.group → should be skipped
                    "policyQuery": {"group": "groups/contractors"},
                    "setting": {
                        "type": "settings/groups_for_business.groups_sharing",
                        "value": {
                            "collaborationCapability": "ANYONE_CAN_ACCESS",
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
                "prowler.providers.googleworkspace.services.groups.groups_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.groups.groups_service import (
                GroupsForBusiness,
            )

            groups = GroupsForBusiness(mock_provider)

            assert groups.policies_fetched is True
            assert groups.policies.collaboration_capability == "DOMAIN_USERS_ONLY"
            assert groups.policies.create_groups_access_level == "ADMIN_ONLY"

    def test_policies_model(self):
        """Test GroupsForBusinessPolicies Pydantic model"""
        from prowler.providers.googleworkspace.services.groups.groups_service import (
            GroupsForBusinessPolicies,
        )

        policies = GroupsForBusinessPolicies(
            collaboration_capability="DOMAIN_USERS_ONLY",
            create_groups_access_level="ADMIN_ONLY",
            owners_can_allow_external_members=False,
            owners_can_allow_incoming_mail_from_public=False,
            view_topics_default_access_level="GROUP_MEMBERS",
            owners_can_hide_groups=False,
            new_groups_are_hidden=False,
        )

        assert policies.collaboration_capability == "DOMAIN_USERS_ONLY"
        assert policies.create_groups_access_level == "ADMIN_ONLY"
        assert policies.owners_can_allow_external_members is False
        assert policies.owners_can_allow_incoming_mail_from_public is False
        assert policies.view_topics_default_access_level == "GROUP_MEMBERS"
        assert policies.owners_can_hide_groups is False
        assert policies.new_groups_are_hidden is False
