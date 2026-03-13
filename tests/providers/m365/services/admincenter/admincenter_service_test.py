import asyncio
from types import SimpleNamespace
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

from prowler.providers.m365.models import M365IdentityInfo
from prowler.providers.m365.services.admincenter.admincenter_service import (
    AdminCenter,
    DirectoryRole,
    Group,
    Organization,
    SharingPolicy,
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


def mock_admincenter_get_sharing_policy(_):
    return SharingPolicy(
        guid="id-1",
        name="Test",
        enabled=False,
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
@patch(
    "prowler.providers.m365.services.admincenter.admincenter_service.AdminCenter._get_sharing_policy",
    new=mock_admincenter_get_sharing_policy,
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

    def test_get_sharing_policy(self):
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
            assert admincenter_client.sharing_policy.guid == "id-1"
            assert admincenter_client.sharing_policy.name == "Test"
            assert admincenter_client.sharing_policy.enabled is False
            admincenter_client.powershell.close()


def test_admincenter__get_users_handles_pagination():
    admincenter_service = AdminCenter.__new__(AdminCenter)

    users_page_one = [
        SimpleNamespace(id="user-1", display_name="User 1"),
        SimpleNamespace(id="user-2", display_name="User 2"),
    ]
    users_page_two = [
        SimpleNamespace(id="user-3", display_name="User 3"),
    ]

    users_response_page_one = SimpleNamespace(
        value=users_page_one,
        odata_next_link="next-link",
    )
    users_response_page_two = SimpleNamespace(
        value=users_page_two, odata_next_link=None
    )

    users_with_url_builder = SimpleNamespace(
        get=AsyncMock(return_value=users_response_page_two)
    )
    with_url_mock = MagicMock(return_value=users_with_url_builder)

    def by_user_id_side_effect(user_id):
        license_details_response = SimpleNamespace(
            value=[SimpleNamespace(sku_part_number=f"SKU-{user_id}")]
        )
        return SimpleNamespace(
            license_details=SimpleNamespace(
                get=AsyncMock(return_value=license_details_response)
            )
        )

    users_builder = SimpleNamespace(
        get=AsyncMock(return_value=users_response_page_one),
        with_url=with_url_mock,
        by_user_id=MagicMock(side_effect=by_user_id_side_effect),
    )

    admincenter_service.client = SimpleNamespace(users=users_builder)

    users = asyncio.run(admincenter_service._get_users())

    assert len(users) == 3
    assert users_builder.get.await_count == 1
    with_url_mock.assert_called_once_with("next-link")
    assert users["user-1"].license == "SKU-user-1"
    assert users["user-3"].license == "SKU-user-3"
