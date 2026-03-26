from unittest.mock import patch

from prowler.providers.googleworkspace.services.directory.directory_service import User
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDirectorySuperAdminOnlyAdminRoles:
    def test_pass_super_admins_not_delegated(self):
        """Test PASS when no super admin has delegated admin roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                is_delegated_admin=False,
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                is_delegated_admin=False,
            ),
            "user1-id": User(
                id="user1-id",
                email="user@test-company.com",
                is_admin=False,
                is_delegated_admin=False,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles import (
                directory_super_admin_only_admin_roles,
            )

            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_only_admin_roles()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "used only for super admin activities" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_super_admin_also_delegated(self):
        """Test FAIL when a super admin also has delegated admin roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                is_delegated_admin=True,
            ),
            "user1-id": User(
                id="user1-id",
                email="user@test-company.com",
                is_admin=False,
                is_delegated_admin=False,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles import (
                directory_super_admin_only_admin_roles,
            )

            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_only_admin_roles()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "admin1@test-company.com" in findings[0].status_extended
            assert "used only for super admin activities" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_multiple_dual_role_admins(self):
        """Test FAIL lists all super admins that also have delegated roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                is_delegated_admin=True,
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                is_delegated_admin=True,
            ),
            "admin3-id": User(
                id="admin3-id",
                email="admin3@test-company.com",
                is_admin=True,
                is_delegated_admin=False,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles import (
                directory_super_admin_only_admin_roles,
            )

            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_only_admin_roles()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "FAIL"
            assert "admin1@test-company.com" in findings[0].status_extended
            assert "admin2@test-company.com" in findings[0].status_extended

    def test_no_findings_when_no_users(self):
        """Test no findings when there are no users"""
        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles import (
                directory_super_admin_only_admin_roles,
            )

            mock_directory_client.users = {}
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_only_admin_roles()
            findings = check.execute()

            assert len(findings) == 0

    def test_delegated_only_admin_not_flagged(self):
        """Test that users who are only delegated admins (not super admins) are ignored"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                is_delegated_admin=False,
            ),
            "delegated1-id": User(
                id="delegated1-id",
                email="delegated@test-company.com",
                is_admin=False,
                is_delegated_admin=True,
            ),
        }

        mock_provider = set_mocked_googleworkspace_provider()

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mock_provider,
            ),
            patch(
                "prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles.directory_client"
            ) as mock_directory_client,
        ):
            from prowler.providers.googleworkspace.services.directory.directory_super_admin_only_admin_roles.directory_super_admin_only_admin_roles import (
                directory_super_admin_only_admin_roles,
            )

            mock_directory_client.users = users
            mock_directory_client.provider = mock_provider

            check = directory_super_admin_only_admin_roles()
            findings = check.execute()

            assert len(findings) == 1
            assert findings[0].status == "PASS"
            assert "delegated@test-company.com" not in findings[0].status_extended
