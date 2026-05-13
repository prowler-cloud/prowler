from unittest.mock import patch

from prowler.providers.googleworkspace.services.directory.directory_service import (
    Role,
    User,
)
from tests.providers.googleworkspace.googleworkspace_fixtures import (
    CUSTOMER_ID,
    DOMAIN,
    set_mocked_googleworkspace_provider,
)

SUPER_ADMIN_ROLE = Role(
    id="13801188331880449",
    name="Super Admin",
    description="Super Admin",
    is_super_admin_role=True,
)
SEED_ADMIN_ROLE = Role(
    id="13801188331880451",
    name="_SEED_ADMIN_ROLE",
    description="Super Admin",
    is_super_admin_role=True,
)
GROUPS_ADMIN_ROLE = Role(
    id="13801188331880450",
    name="_GROUPS_ADMIN_ROLE",
    description="Groups Administrator",
    is_super_admin_role=False,
)
USER_MANAGEMENT_ADMIN_ROLE = Role(
    id="13801188331880452",
    name="_USER_MANAGEMENT_ADMIN_ROLE",
    description="User Management Administrator",
    is_super_admin_role=False,
)
CUSTOM_ROLE_NO_DESCRIPTION = Role(
    id="13801188331880453",
    name="custom-helpdesk-role",
    description="",
    is_super_admin_role=False,
)


class TestDirectorySuperAdminOnlyAdminRoles:
    def test_pass_super_admins_only_super_admin_role(self):
        """Test PASS when super admins have only the Super Admin role"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE],
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE],
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
            assert findings[0].resource_id == CUSTOMER_ID
            assert findings[0].customer_id == CUSTOMER_ID
            assert findings[0].resource == mock_provider.domain_resource.dict()

    def test_pass_super_admin_with_seed_admin_role(self):
        """Test PASS when a super admin only holds _SEED_ADMIN_ROLE.

        _SEED_ADMIN_ROLE is auto-assigned by Google to the original domain
        creator and has isSuperAdminRole=True, so it must not count as an
        "extra" role.
        """
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="playground@prowler.cloud",
                is_admin=True,
                role_assignments=[SEED_ADMIN_ROLE],
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
            assert "_SEED_ADMIN_ROLE" not in findings[0].status_extended

    def test_pass_super_admin_with_both_super_admin_and_seed_admin(self):
        """Test PASS when admin holds both Super Admin and _SEED_ADMIN_ROLE"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="playground@prowler.cloud",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE, SEED_ADMIN_ROLE],
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

    def test_fail_super_admin_with_additional_roles(self):
        """Test FAIL when a super admin also has additional admin roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE, GROUPS_ADMIN_ROLE],
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
            assert "Groups Administrator" in findings[0].status_extended
            assert "_GROUPS_ADMIN_ROLE" not in findings[0].status_extended
            assert "used only for super admin activities" in findings[0].status_extended
            assert findings[0].resource_name == "admin1@test-company.com"
            assert findings[0].resource_id == "admin1-id"
            assert findings[0].customer_id == CUSTOMER_ID

    def test_fail_seed_admin_with_additional_roles(self):
        """Test FAIL when a _SEED_ADMIN_ROLE holder also has extra roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="playground@prowler.cloud",
                is_admin=True,
                role_assignments=[SEED_ADMIN_ROLE, GROUPS_ADMIN_ROLE],
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
            assert "playground@prowler.cloud" in findings[0].status_extended
            assert "Groups Administrator" in findings[0].status_extended
            assert "_GROUPS_ADMIN_ROLE" not in findings[0].status_extended
            assert "_SEED_ADMIN_ROLE" not in findings[0].status_extended
            assert findings[0].resource_name == "playground@prowler.cloud"
            assert findings[0].resource_id == "admin1-id"

    def test_fail_multiple_super_admins_with_extra_roles(self):
        """Test FAIL lists all super admins that have additional roles"""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE, GROUPS_ADMIN_ROLE],
            ),
            "admin2-id": User(
                id="admin2-id",
                email="admin2@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE, USER_MANAGEMENT_ADMIN_ROLE],
            ),
            "admin3-id": User(
                id="admin3-id",
                email="admin3@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE],
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

            assert len(findings) == 2
            assert all(finding.status == "FAIL" for finding in findings)
            assert findings[0].resource_name == "admin1@test-company.com"
            assert findings[1].resource_name == "admin2@test-company.com"
            assert "admin3@test-company.com" not in findings[0].status_extended
            assert "admin3@test-company.com" not in findings[1].status_extended

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
                role_assignments=[SUPER_ADMIN_ROLE],
            ),
            "delegated1-id": User(
                id="delegated1-id",
                email="delegated@test-company.com",
                is_admin=False,
                role_assignments=[GROUPS_ADMIN_ROLE],
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

    def test_fail_custom_role_without_description_falls_back_to_name(self):
        """A custom role with an empty description should be displayed
        using its name as a fall-back, so the FAIL message is never blank
        for users that genuinely hold extra roles."""
        users = {
            "admin1-id": User(
                id="admin1-id",
                email="admin1@test-company.com",
                is_admin=True,
                role_assignments=[SUPER_ADMIN_ROLE, CUSTOM_ROLE_NO_DESCRIPTION],
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
            assert "custom-helpdesk-role" in findings[0].status_extended
            assert findings[0].resource_name == "admin1@test-company.com"
