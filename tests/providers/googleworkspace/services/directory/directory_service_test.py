from unittest.mock import MagicMock, patch

from tests.providers.googleworkspace.googleworkspace_fixtures import (
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
