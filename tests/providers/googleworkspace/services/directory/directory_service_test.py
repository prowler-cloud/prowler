from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
    GROUPS_ADMIN_ROLE_ID,
    ROLE_GROUPS_ADMIN,
    ROLE_SEED_ADMIN,
    ROLE_SUPER_ADMIN,
    SEED_ADMIN_ROLE_ID,
    SUPER_ADMIN_ROLE_ID,
    USER_1,
    USER_2,
    USER_3,
    set_mocked_googleworkspace_provider,
)


class TestDirectoryService:
    def test_directory_list_users(self):
        """Test listing users from Directory API"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": [USER_1, USER_2, USER_3]}
        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        # Mock roles response
        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {
            "items": [ROLE_SUPER_ADMIN, ROLE_GROUPS_ADMIN]
        }
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {
            "items": [
                {"assignedTo": "user1-id", "roleId": SUPER_ADMIN_ROLE_ID},
                {"assignedTo": "user2-id", "roleId": SUPER_ADMIN_ROLE_ID},
            ]
        }
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            assert len(directory.users) == 3
            assert "user1-id" in directory.users
            assert "user2-id" in directory.users
            assert "user3-id" in directory.users

            admin_users = [user for user in directory.users.values() if user.is_admin]
            assert len(admin_users) == 2
            assert directory.users["user1-id"].email == "admin@test-company.com"
            assert directory.users["user1-id"].is_admin is True
            assert directory.users["user3-id"].is_admin is False

    def test_directory_empty_users_list(self):
        """Test handling empty users list"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": []}
        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        # Mock roles response
        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {"items": []}
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {"items": []}
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            assert len(directory.users) == 0

    def test_directory_api_error_handling(self):
        """Test handling of API errors"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()
        mock_service.users().list.side_effect = Exception("API Error")

        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {"items": []}
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {"items": []}
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            assert len(directory.users) == 0

    def test_user_model(self):
        """Test User Pydantic model"""
        from prowler.providers.googleworkspace.services.directory.directory_service import (
            User,
        )

        user = User(
            id="test-id",
            email="test@test-company.com",
            is_admin=True,
        )

        assert user.id == "test-id"
        assert user.email == "test@test-company.com"
        assert user.is_admin is True
        assert user.role_assignments == []

    def test_directory_list_roles(self):
        """Test that _list_roles correctly builds a roleId-to-roleName mapping"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()

        # Mock empty users
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": []}
        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        # Mock roles response
        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {
            "items": [ROLE_SUPER_ADMIN, ROLE_GROUPS_ADMIN]
        }
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {"items": []}
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            super_admin_role = directory._roles[SUPER_ADMIN_ROLE_ID]
            assert super_admin_role.name == "Super Admin"
            assert super_admin_role.description == "Super Admin"
            assert super_admin_role.is_super_admin_role is True

            groups_admin_role = directory._roles[GROUPS_ADMIN_ROLE_ID]
            assert groups_admin_role.name == "_GROUPS_ADMIN_ROLE"
            assert groups_admin_role.description == "Groups Administrator"
            assert groups_admin_role.is_super_admin_role is False

    def test_directory_role_assignments_populated(self):
        """Test that role assignments are fetched and resolved for super admins"""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()

        # Mock users - one super admin
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": [USER_1]}
        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        # Mock roles
        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {
            "items": [ROLE_SUPER_ADMIN, ROLE_GROUPS_ADMIN]
        }
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {
            "items": [
                {"assignedTo": "user1-id", "roleId": SUPER_ADMIN_ROLE_ID},
                {"assignedTo": "user1-id", "roleId": GROUPS_ADMIN_ROLE_ID},
            ]
        }
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            user = directory.users["user1-id"]
            role_names = [r.name for r in user.role_assignments]
            role_descriptions = [r.description for r in user.role_assignments]
            assert "Super Admin" in role_names
            assert "_GROUPS_ADMIN_ROLE" in role_names
            assert "Groups Administrator" in role_descriptions
            assert len(user.role_assignments) == 2
            assert user.is_admin is True

    def test_directory_second_super_admin_detected_via_role_assignments(self):
        """Regression: a second super admin whose users.list().isAdmin still
        reads False (e.g. API propagation lag, or only holding
        _SEED_ADMIN_ROLE) must still be recognised as a super admin through
        the Role Assignments API, AND any extra non-super-admin roles they
        hold must be surfaced on their User object."""
        mock_provider = set_mocked_googleworkspace_provider()
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}
        mock_session = MagicMock()
        mock_session.credentials = MagicMock()
        mock_provider.session = mock_session

        mock_service = MagicMock()

        stale_user_1 = {
            "id": "user1-id",
            "primaryEmail": "admin1@test-company.com",
            "isAdmin": False,
        }
        stale_user_2 = {
            "id": "user2-id",
            "primaryEmail": "admin2@test-company.com",
            "isAdmin": False,
        }
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": [stale_user_1, stale_user_2]}
        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        mock_roles_list = MagicMock()
        mock_roles_list.execute.return_value = {
            "items": [ROLE_SUPER_ADMIN, ROLE_SEED_ADMIN, ROLE_GROUPS_ADMIN]
        }
        mock_service.roles().list.return_value = mock_roles_list
        mock_service.roles().list_next.return_value = None

        mock_ra = MagicMock()
        mock_ra.execute.return_value = {
            "items": [
                {"assignedTo": "user1-id", "roleId": SEED_ADMIN_ROLE_ID},
                {"assignedTo": "user2-id", "roleId": SUPER_ADMIN_ROLE_ID},
                {"assignedTo": "user2-id", "roleId": GROUPS_ADMIN_ROLE_ID},
            ]
        }
        mock_service.roleAssignments().list.return_value = mock_ra
        mock_service.roleAssignments().list_next.return_value = None

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
                return_value=mock_service,
            ),
        ):
            from prowler.providers.googleworkspace.services.directory.directory_service import (
                Directory,
            )

            directory = Directory(mock_provider)

            user1 = directory.users["user1-id"]
            user2 = directory.users["user2-id"]
            assert user1.is_admin is True
            assert user2.is_admin is True

            assert [r.name for r in user1.role_assignments] == ["_SEED_ADMIN_ROLE"]
            user2_role_names = {r.name for r in user2.role_assignments}
            assert user2_role_names == {"Super Admin", "_GROUPS_ADMIN_ROLE"}
