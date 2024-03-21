from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import DOMAIN


class Test_entra_users_less_than_five_global_admins:
    def test_entra_no_tenants(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins import (
                entra_users_less_than_five_global_admins,
            )

            entra_client.directory_roles = {}

            check = entra_users_less_than_five_global_admins()
            result = check.execute()
            assert len(result) == 0

    def test_entra_tenant_empty(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins import (
                entra_users_less_than_five_global_admins,
            )

            entra_client.directory_roles = {DOMAIN: {}}

            check = entra_users_less_than_five_global_admins()
            result = check.execute()
            assert len(result) == 0

    def test_entra_less_than_five_global_admins(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )
            from prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins import (
                entra_users_less_than_five_global_admins,
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

            check = entra_users_less_than_five_global_admins()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "There are 2 global administrators."
            assert result[0].subscription == f"Tenant: '{DOMAIN}'"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id

    def test_entra_more_than_five_global_admins(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )
            from prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins import (
                entra_users_less_than_five_global_admins,
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

            check = entra_users_less_than_five_global_admins()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are 6 global administrators. It should be less than five."
            )
            assert result[0].subscription == f"Tenant: '{DOMAIN}'"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id

    def test_entra_exactly_five_global_admins(self):
        entra_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins.entra_client",
            new=entra_client,
        ):
            from prowler.providers.azure.services.entra.entra_service import (
                DirectoryRole,
                User,
            )
            from prowler.providers.azure.services.entra.entra_users_less_than_five_global_admins.entra_users_less_than_five_global_admins import (
                entra_users_less_than_five_global_admins,
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

            check = entra_users_less_than_five_global_admins()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are 5 global administrators. It should be less than five."
            )
            assert result[0].subscription == f"Tenant: '{DOMAIN}'"
            assert result[0].resource_name == "Global Administrator"
            assert result[0].resource_id == id
