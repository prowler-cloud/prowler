from unittest import mock

from prowler.providers.microsoft365.services.entra.entra_service import AdminRoles, User
from tests.providers.microsoft365.microsoft365_fixtures import (
    set_mocked_microsoft365_provider,
)


class Test_entra_admin_users_cloud_only:
    def test_admin_accounts_are_cloud_only(self):
        """
        Test when all admin accounts are cloud-only:
        The check should PASS because there are no non-cloud-only admin accounts.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            entra_client.users = {
                "user-1": User(
                    id="user-1",
                    name="User 1",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
                "user-2": User(
                    id="user-2",
                    name="User 2",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
                "user-3": User(
                    id="user-3",
                    name="User 3",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
            }

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "There is no admin users with a non-cloud-only account."
            )
            assert result[0].resource_id == "cloudOnlyAccount"
            assert result[0].location == "global"
            assert result[0].resource_name == "Cloud-only account"
            assert result[0].resource == {}

    def test_some_admin_accounts_are_not_cloud(self):
        """
        Test when some admin accounts are not cloud-only:
        The check should FAIL because there are non-cloud-only admin accounts.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            entra_client.users = {
                "user-1": User(
                    id="user-1",
                    name="User 1",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
                "user-2": User(
                    id="user-2",
                    name="User 2",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=True,
                ),
                "user-3": User(
                    id="user-3",
                    name="User 3",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
            }

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Users with admin roles have non-cloud-only accounts: user-2"
            )
            assert result[0].resource_id == "cloudOnlyAccount"
            assert result[0].location == "global"
            assert result[0].resource_name == "Cloud-only account"
            assert result[0].resource == {}

    def test_all_admin_account_are_not_cloud(self):
        """
        Test when all admin accounts are not cloud-only:
        The check should FAIL because all admin accounts are non-cloud-only.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            entra_client.users = {
                "user-1": User(
                    id="user-1",
                    name="User 1",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=True,
                ),
                "user-2": User(
                    id="user-2",
                    name="User 2",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=True,
                ),
                "user-3": User(
                    id="user-3",
                    name="User 3",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=True,
                ),
            }

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Users with admin roles have non-cloud-only accounts: user-1, user-2, user-3"
            )
            assert result[0].resource_id == "cloudOnlyAccount"
            assert result[0].location == "global"
            assert result[0].resource_name == "Cloud-only account"
            assert result[0].resource == {}

    def test_only_user_accounts_are_not_cloud(self):
        """
        Test when only user accounts are not cloud-only:
        The check should PASS because there are no non-cloud-only admin accounts.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            entra_client.users = {
                "user-1": User(
                    id="user-1",
                    name="User 1",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
                "user-2": User(
                    id="user-2",
                    name="User 2",
                    directory_roles_ids=[AdminRoles.GLOBAL_ADMINISTRATOR.value],
                    on_premises_sync_enabled=False,
                ),
                "user-3": User(
                    id="user-3",
                    name="User 3",
                    directory_roles_ids=["user-id-role"],
                    on_premises_sync_enabled=True,
                ),
            }

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "There is no admin users with a non-cloud-only account."
            )
            assert result[0].resource_id == "cloudOnlyAccount"
            assert result[0].location == "global"
            assert result[0].resource_name == "Cloud-only account"
            assert result[0].resource == {}

    def test_no_admin_accounts(self):
        """
        Test when there are no admin accounts:
        The check should PASS because there are no non-cloud-only admin accounts.
        """
        entra_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            entra_client.users = {
                "user-1": User(
                    id="user-1",
                    name="User 1",
                    directory_roles_ids=["user-id-role"],
                    on_premises_sync_enabled=True,
                ),
                "user-2": User(
                    id="user-2",
                    name="User 2",
                    directory_roles_ids=["user-id-role"],
                    on_premises_sync_enabled=False,
                ),
                "user-3": User(
                    id="user-3",
                    name="User 3",
                    directory_roles_ids=["user-id-role"],
                    on_premises_sync_enabled=False,
                ),
            }

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "There is no admin users with a non-cloud-only account."
            )
            assert result[0].resource_id == "cloudOnlyAccount"
            assert result[0].location == "global"
            assert result[0].resource_name == "Cloud-only account"
            assert result[0].resource == {}

    def test_no_users(self):
        """
        Test when there are no users:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.users = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_microsoft365_provider(),
            ),
            mock.patch(
                "prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.microsoft365.services.entra.entra_admin_users_cloud_only.entra_admin_users_cloud_only import (
                entra_admin_users_cloud_only,
            )

            check = entra_admin_users_cloud_only()
            result = check.execute()

            assert len(result) == 0
            assert result == []
