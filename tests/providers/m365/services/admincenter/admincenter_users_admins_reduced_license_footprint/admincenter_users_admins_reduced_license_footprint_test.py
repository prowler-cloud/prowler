from unittest import mock
from uuid import uuid4

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_admincenter_users_admins_reduced_license_footprint:
    def test_admincenter_no_users(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint import (
                admincenter_users_admins_reduced_license_footprint,
            )

            admincenter_client.users = {}

            check = admincenter_users_admins_reduced_license_footprint()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_user_no_admin(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                User,
            )
            from prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint import (
                admincenter_users_admins_reduced_license_footprint,
            )

            id_user1 = str(uuid4())

            admincenter_client.users = {
                id_user1: User(
                    id=id_user1,
                    name="User1",
                    directory_roles=["Exchange User"],
                    license="O365 BUSINESS",
                ),
            }

            check = admincenter_users_admins_reduced_license_footprint()
            result = check.execute()
            assert len(result) == 0

    def test_admincenter_user_admin_compliant_license(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                User,
            )
            from prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint import (
                admincenter_users_admins_reduced_license_footprint,
            )

            id_user1 = str(uuid4())

            admincenter_client.users = {
                id_user1: User(
                    id=id_user1,
                    name="User1",
                    directory_roles=["Global Administrator"],
                    license="AAD_PREMIUM",
                ),
            }

            check = admincenter_users_admins_reduced_license_footprint()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "User User1 has administrative roles Global Administrator and a valid license: AAD_PREMIUM."
            )
            assert result[0].resource == admincenter_client.users[id_user1].dict()
            assert result[0].resource_name == "User1"
            assert result[0].resource_id == id_user1
            assert result[0].location == "global"

    def test_admincenter_user_admin_non_compliant_license(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                User,
            )
            from prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint import (
                admincenter_users_admins_reduced_license_footprint,
            )

            id_user1 = str(uuid4())

            admincenter_client.users = {
                id_user1: User(
                    id=id_user1,
                    name="User1",
                    directory_roles=["Global Administrator"],
                    license="O365 BUSINESS",
                ),
            }

            check = admincenter_users_admins_reduced_license_footprint()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "User User1 has administrative roles Global Administrator and an invalid license: O365 BUSINESS."
            )
            assert result[0].resource == admincenter_client.users[id_user1].dict()
            assert result[0].resource_name == "User1"
            assert result[0].resource_id == id_user1
            assert result[0].location == "global"

    def test_admincenter_user_admin_no_license(self):
        admincenter_client = mock.MagicMock
        admincenter_client.audited_tenant = "audited_tenant"
        admincenter_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint.admincenter_client",
                new=admincenter_client,
            ),
        ):
            from prowler.providers.m365.services.admincenter.admincenter_service import (
                User,
            )
            from prowler.providers.m365.services.admincenter.admincenter_users_admins_reduced_license_footprint.admincenter_users_admins_reduced_license_footprint import (
                admincenter_users_admins_reduced_license_footprint,
            )

            id_user1 = str(uuid4())

            admincenter_client.users = {
                id_user1: User(
                    id=id_user1,
                    name="User1",
                    directory_roles=["Global Administrator"],
                    license=None,
                ),
            }

            check = admincenter_users_admins_reduced_license_footprint()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "User User1 has administrative roles Global Administrator and does not have a license."
            )
            assert result[0].resource == admincenter_client.users[id_user1].dict()
            assert result[0].resource_name == "User1"
            assert result[0].resource_id == id_user1
            assert result[0].location == "global"
