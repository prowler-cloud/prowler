from unittest import mock
from unittest.mock import patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.admincenter.admincenter_service import (
    AdminCenter,
    DirectoryRole,
    Group,
    Organization,
    User,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


async def mock_admincenter_get_users(_):
    return {
        "user-1@tenant1.es": User(
            id="id-1",
            name="User 1",
            directory_roles=[],
        ),
    }


async def mock_admincenter_get_directory_roles(_):
    return {
        "GlobalAdministrator": DirectoryRole(
            id="id-directory-role",
            name="GlobalAdministrator",
            members=[],
        )
    }


async def mock_admincenter_get_groups(_):
    return {
        "id-1": Group(id="id-1", name="Test", visibility="Public"),
    }


def mock_admincenter_get_organization(_):
    return Organization(
        guid="id-1",
        name="Test",
        customer_lockbox_enabled=False,
    )


@patch(
    "prowler.providers.m365.services.admincenter.admincenter_service.AdminCenter._get_users",
    new=mock_admincenter_get_users,
)
@patch(
    "prowler.providers.m365.services.admincenter.admincenter_service.AdminCenter._get_directory_roles",
    new=mock_admincenter_get_directory_roles,
)
@patch(
    "prowler.providers.m365.services.admincenter.admincenter_service.AdminCenter._get_groups",
    new=mock_admincenter_get_groups,
)
@patch(
    "prowler.providers.m365.services.admincenter.admincenter_service.AdminCenter._get_organization_config",
    new=mock_admincenter_get_organization,
)
class Test_AdminCenter_Service:
    def test_get_client(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_users(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            admincenter_client = AdminCenter(set_mocked_m365_provider())
            assert len(admincenter_client.users) == 1
            assert admincenter_client.users["user-1@tenant1.es"].id == "id-1"
            assert admincenter_client.users["user-1@tenant1.es"].name == "User 1"

    def test_get_group_settings(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            admincenter_client = AdminCenter(set_mocked_m365_provider())
            assert len(admincenter_client.groups) == 1
            assert admincenter_client.groups["id-1"].id == "id-1"
            assert admincenter_client.groups["id-1"].name == "Test"
            assert admincenter_client.groups["id-1"].visibility == "Public"

    def test_get_directory_roles(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            admincenter_client = AdminCenter(set_mocked_m365_provider())
            assert (
                admincenter_client.directory_roles["GlobalAdministrator"].id
                == "id-directory-role"
            )
            assert (
                len(admincenter_client.directory_roles["GlobalAdministrator"].members)
                == 0
            )

    def test_get_organization(self):
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )
            assert admincenter_client.organization_config.guid == "id-1"
            assert admincenter_client.organization_config.name == "Test"
            assert (
                admincenter_client.organization_config.customer_lockbox_enabled is False
            )
            admincenter_client.powershell.close()
