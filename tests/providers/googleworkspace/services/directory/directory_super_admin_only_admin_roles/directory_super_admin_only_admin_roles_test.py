from unittest.mock import patch

from prowler.providers.googleworkspace.services.directory.directory_service import User
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)


class TestDirectorySuperAdminOnlyAdminRoles:
    def test_pass_super_admins_only_super_admin_role(self):
        """Test PASS when super admins have only the Super Admin role"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin"],
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin"],
            ),
            "user1-id": User(
                id="user1-id",
                email="user@test-company.com",
                is_admin=False,
                role_assignments=[],
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

    def test_fail_super_admin_with_additional_roles(self):
        """Test FAIL when a super admin also has additional admin roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin", "Groups Admin"],
            ),
            "user1-id": User(
                id="user1-id",
                email="user@test-company.com",
                is_admin=False,
                role_assignments=[],
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
            assert "Groups Admin" in findings[0].status_extended
            assert "used only for super admin activities" in findings[0].status_extended
            assert findings[0].resource_name == DOMAIN
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_multiple_super_admins_with_extra_roles(self):
        """Test FAIL lists all super admins that have additional roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin", "Groups Admin"],
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin", "User Management Admin"],
            ),
            "admin3-id": User(
                id="admin3-id",
                email="admin3@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin"],
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
            assert "admin3@test-company.com" not in findings[0].status_extended

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

    def test_non_super_admin_with_roles_not_flagged(self):
        """Test that users who are not super admins are ignored even if they have roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=["Super Admin"],
            ),
            "delegated1-id": User(
                id="delegated1-id",
                email="delegated@test-company.com",
                is_admin=False,
                role_assignments=["Groups Admin"],
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

    def test_pass_super_admin_with_empty_role_assignments(self):
        """Test PASS when super admin has no role assignments (edge case)"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=[],
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
