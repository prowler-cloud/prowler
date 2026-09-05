from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    DOMAIN,
    TENANT_IDS,
    set_mocked_azure_provider,
)


class Test_entra_global_admin_in_less_than_five_users:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )

            entra_client.directory_roles = {}

            entra_client.users = {}

            check = entra_global_admin_in_less_than_five_users()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )

            entra_client.directory_roles = {DOMAIN: {}}

            entra_client.users = {DOMAIN: {}}

            check = entra_global_admin_in_less_than_five_users()
            result = check.execute()
            assert len(result) == 0

    def test_entra_less_than_five_global_admins(self):
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )

            id = str(uuid4())
            id_user1 = str(uuid4())
            id_user2 = str(uuid4())

            entra_client.directory_roles = {
                DOMAIN: {
                    "Global Administrator": DirectoryRole(
                        id=id,
                        members=[
                            User(id=id_user1, name="User1"),
                            User(id=id_user2, name="User2"),
                        ],
                    )
                }
            }

            entra_client.users = {
                DOMAIN: {
                    f"User1@{DOMAIN}": User(id=id_user1, name="User1"),
                    f"User2@{DOMAIN}": User(id=id_user2, name="User2"),
                }
            }

            check = entra_global_admin_in_less_than_five_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "There are 2 global administrators."
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id

    def test_entra_more_than_five_global_admins(self):
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )

            id = str(uuid4())
            id_user1 = str(uuid4())
            id_user2 = str(uuid4())
            id_user3 = str(uuid4())
            id_user4 = str(uuid4())
            id_user5 = str(uuid4())
            id_user6 = str(uuid4())

            entra_client.directory_roles = {
                DOMAIN: {
                    "Global Administrator": DirectoryRole(
                        id=id,
                        members=[
                            User(id=id_user1, name="User1"),
                            User(id=id_user2, name="User2"),
                            User(id=id_user3, name="User3"),
                            User(id=id_user4, name="User4"),
                            User(id=id_user5, name="User5"),
                            User(id=id_user6, name="User6"),
                        ],
                    )
                }
            }

            entra_client.users = {
                DOMAIN: {
                    f"User1@{DOMAIN}": User(id=id_user1, name="User1"),
                    f"User2@{DOMAIN}": User(id=id_user2, name="User2"),
                    f"User3@{DOMAIN}": User(id=id_user3, name="User3"),
                    f"User4@{DOMAIN}": User(id=id_user4, name="User4"),
                    f"User5@{DOMAIN}": User(id=id_user5, name="User5"),
                    f"User6@{DOMAIN}": User(id=id_user6, name="User6"),
                }
            }

            check = entra_global_admin_in_less_than_five_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are 6 global administrators. It should be less than five."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id

    def test_entra_exactly_five_global_admins(self):
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.users_retrieval_errors = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )

            id = str(uuid4())
            id_user1 = str(uuid4())
            id_user2 = str(uuid4())
            id_user3 = str(uuid4())
            id_user4 = str(uuid4())
            id_user5 = str(uuid4())

            entra_client.directory_roles = {
                DOMAIN: {
                    "Global Administrator": DirectoryRole(
                        id=id,
                        members=[
                            User(id=id_user1, name="User1"),
                            User(id=id_user2, name="User2"),
                            User(id=id_user3, name="User3"),
                            User(id=id_user4, name="User4"),
                            User(id=id_user5, name="User5"),
                        ],
                    )
                }
            }

            entra_client.users = {
                DOMAIN: {
                    f"User1@{DOMAIN}": User(id=id_user1, name="User1"),
                    f"User2@{DOMAIN}": User(id=id_user2, name="User2"),
                    f"User3@{DOMAIN}": User(id=id_user3, name="User3"),
                    f"User4@{DOMAIN}": User(id=id_user4, name="User4"),
                    f"User5@{DOMAIN}": User(id=id_user5, name="User5"),
                }
            }

            check = entra_global_admin_in_less_than_five_users()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are 5 global administrators. It should be less than five."
            )
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id

    def test_entra_users_retrieval_error_reports_single_manual(self):
        """Graph could not return the tenant's users -> one tenant-level MANUAL."""
        entra_client = mock.MagicMock
        entra_client.resource_groups = {}
        entra_client.tenant_ids = [TENANT_IDS[0]]
        entra_client.users_retrieval_errors = {DOMAIN: "ODataError HTTP 503"}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.azure.services.entra.entra_global_admin_in_less_than_five_users.entra_global_admin_in_less_than_five_users import (
                entra_global_admin_in_less_than_five_users,
            )
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
            )

            # Directory roles were retrieved, but every member was filtered
            # out because the users could not be fetched: without the error
            # tracking this would be a false PASS with 0 administrators.
            entra_client.directory_roles = {
                DOMAIN: {
                    "Global Administrator": DirectoryRole(id=str(uuid4()), members=[])
                }
            }
            entra_client.users = {DOMAIN: {}}

            result = entra_global_admin_in_less_than_five_users().execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "did not return the tenant's users" in result[0].status_extended
            assert "503" in result[0].status_extended
            assert result[0].subscription == f"Tenant: {DOMAIN}"
            assert result[0].resource_id == TENANT_IDS[0]
