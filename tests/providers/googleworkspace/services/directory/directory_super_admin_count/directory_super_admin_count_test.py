from unittest.mock import MagicMock, patch

from prowler.providers.googleworkspace.models import GoogleWorkspaceIdentityInfo
from prowler.providers.googleworkspace.services.directory.directory_service import User
from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
    directory_super_admin_count,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DELEGATED_USER,
    DOMAIN,
)


class TestDirectorySuperAdminCount:
    def test_directory_super_admin_count_pass_2_admins(self):
        """Test PASS when there are 2 super admins (within range)"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create 2 admin users and 1 regular user
        users = {
            "user1-id": User(
                id="user1-id",
                email="admin1@test-company.com",
                full_name="Admin 1",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            ),
            "user2-id": User(
                id="user2-id",
                email="admin2@test-company.com",
                full_name="Admin 2",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            ),
            "user3-id": User(
                id="user3-id",
                email="user@test-company.com",
                full_name="Regular User",
                is_admin=False,
                customer_id=CUSTOMER_ID,
            ),
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "2 super administrator(s)" in findings[0].status_extended
            assert "within the recommended range" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_directory_super_admin_count_pass_4_admins(self):
        """Test PASS when there are 4 super admins (within range)"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create 4 admin users
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                full_name=f"Admin {i}",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            )
            for i in range(1, 5)
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "4 super administrator(s)" in findings[0].status_extended
            assert "within the recommended range" in findings[0].status_extended

    def test_directory_super_admin_count_fail_0_admins(self):
        """Test FAIL when there are 0 super admins"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create only regular users
        users = {
            "user1-id": User(
                id="user1-id",
                email="user1@test-company.com",
                full_name="Regular User 1",
                is_admin=False,
                customer_id=CUSTOMER_ID,
            ),
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "only 0 super administrator(s)" in findings[0].status_extended
            assert "single point of failure" in findings[0].status_extended

    def test_directory_super_admin_count_fail_1_admin(self):
        """Test FAIL when there is only 1 super admin"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create 1 admin user
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin@test-company.com",
                full_name="Admin",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            ),
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "only 1 super administrator(s)" in findings[0].status_extended
            assert "single point of failure" in findings[0].status_extended

    def test_directory_super_admin_count_fail_5_admins(self):
        """Test FAIL when there are 5 super admins (too many)"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create 5 admin users
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                full_name=f"Admin {i}",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            )
            for i in range(1, 6)
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "5 super administrator(s)" in findings[0].status_extended
            assert "minimize security risk" in findings[0].status_extended

    def test_directory_super_admin_count_fail_10_admins(self):
        """Test FAIL when there are 10 super admins (way too many)"""
        # Create mock provider
        mock_provider = MagicMock()
        mock_provider.identity = GoogleWorkspaceIdentityInfo(
            domain=DOMAIN,
            customer_id=CUSTOMER_ID,
            delegated_user=DELEGATED_USER,
            profile="default",
        )

        # Create 10 admin users
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                full_name=f"Admin {i}",
                is_admin=True,
                customer_id=CUSTOMER_ID,
            )
            for i in range(1, 11)
        }

        with patch(
            "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
        ) as mock_directory_client:
            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "10 super administrator(s)" in findings[0].status_extended
