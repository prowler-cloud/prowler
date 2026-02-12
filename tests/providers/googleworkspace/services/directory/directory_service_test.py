from unittest.mock import MagicMock, patch

from prowler.providers.googleworkspace.models import GoogleWorkspaceIdentityInfo
from prowler.providers.googleworkspace.services.directory.directory_service import (
    Directory,
    User,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DELEGATED_USER,
    DOMAIN,
    USER_1,
    USER_2,
    USER_3,
)


class TestDirectoryService:
    def test_directory_list_users(self):
        """Test listing users from Directory API"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}

        # Mock credentials
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        # Mock API response
        mock_service = MagicMock()
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": [USER_1, USER_2, USER_3]}

        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None  # No more pages

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
            return_value=mock_service,
        ):
            directory = Directory(mock_provider)

            # Verify users were loaded
            assert len(directory.users) == 3
            assert "user1-id" in directory.users
            assert "user2-id" in directory.users
            assert "user3-id" in directory.users

            # Verify admin users
            admin_users = [user for user in directory.users.values() if user.is_admin]
            assert len(admin_users) == 2
            assert directory.users["user1-id"].email == "admin@test-company.com"
            assert directory.users["user1-id"].is_admin is True
            assert directory.users["user3-id"].is_admin is False

    def test_directory_empty_users_list(self):
        """Test handling empty users list"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}

        # Mock credentials
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        # Mock API response with no users
        mock_service = MagicMock()
        mock_users_list = MagicMock()
        mock_users_list.execute.return_value = {"users": []}

        mock_service.users().list.return_value = mock_users_list
        mock_service.users().list_next.return_value = None

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
            return_value=mock_service,
        ):
            directory = Directory(mock_provider)

            # Verify no users were loaded
            assert len(directory.users) == 0

    def test_directory_api_error_handling(self):
        """Test handling of API errors"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )
        mock_provider.audit_config = {}
        mock_provider.fixer_config = {}

        # Mock credentials
        mock_credentials = MagicMock()
        mock_session = MagicMock()
        mock_session.credentials = mock_credentials
        mock_provider.session = mock_session

        # Mock API error
        mock_service = MagicMock()
        mock_service.users().list.side_effect = Exception("API Error")

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_service.GoogleWorkspaceService._build_service",
            return_value=mock_service,
        ):
            directory = Directory(mock_provider)

            # Verify empty users dict on error
            assert len(directory.users) == 0

    def test_user_model(self):
        """Test User Pydantic model"""
        user = User(
            id="test-id",
            email="test@test-company.com",
            full_name="Test User",
            given_name="Test",
            family_name="User",
            is_admin=True,
            is_delegated_admin=False,
            is_suspended=False,
            is_archived=False,
            creation_time="2020-01-01T00:00:00.000Z",
            last_login_time="2024-01-01T00:00:00.000Z",
            organizational_unit="/",
            is_mailbox_setup=True,
            customer_id=CUSTOMER_ID,
        )

        assert user.id == "test-id"
        assert user.email == "test@test-company.com"
        assert user.full_name == "Test User"
        assert user.is_admin is True
        assert user.is_suspended is False
