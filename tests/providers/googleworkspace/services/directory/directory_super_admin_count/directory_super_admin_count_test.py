from unittest.mock import patch

from prowler.providers.googleworkspace.services.directory.directory_service import User
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDirectorySuperAdminCount:
    def test_directory_super_admin_count_pass_2_admins(self):
        """Test PASS when there are 2 super admins (within range)"""
        users = {
            "user1-id": User(
                id="user1-id",
                email="admin1@test-company.com",
                is_admin=True,
            ),
            "user2-id": User(
                id="user2-id",
                email="admin2@test-company.com",
                is_admin=True,
            ),
            "user3-id": User(
                id="user3-id",
                email="user@test-company.com",
                is_admin=False,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

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
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                is_admin=True,
            )
            for i in range(1, 5)
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

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
        users = {
            "user1-id": User(
                id="user1-id",
                email="user1@test-company.com",
                is_admin=False,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

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
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin@test-company.com",
                is_admin=True,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

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
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                is_admin=True,
            )
            for i in range(1, 6)
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

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
        users = {
            f"admin{i}-id": User(
                id=f"admin{i}-id",
                email=f"admin{i}@test-company.com",
                is_admin=True,
            )
            for i in range(1, 11)
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_count.directory_super_admin_count import (
                directory_super_admin_count,
            )

            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_count()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "10 super administrator(s)" in findings[0].status_extended
