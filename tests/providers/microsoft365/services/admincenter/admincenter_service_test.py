from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.admincenter.admincenter_service import (
    AdminCenter,
    DirectoryRole,
    Group,
    User,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


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


@patch(
    "prowler.providers.microsoft365.services.admincenter.admincenter_service.AdminCenter._get_users",
    new=mock_admincenter_get_users,
)
@patch(
    "prowler.providers.microsoft365.services.admincenter.admincenter_service.AdminCenter._get_directory_roles",
    new=mock_admincenter_get_directory_roles,
)
@patch(
    "prowler.providers.microsoft365.services.admincenter.admincenter_service.AdminCenter._get_groups",
    new=mock_admincenter_get_groups,
)
class Test_AdminCenter_Service:
    def test_get_client(self):
        admincenter_client = AdminCenter(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_users(self):
        admincenter_client = AdminCenter(set_mocked_microsoft365_provider())
        assert len(admincenter_client.users) == 1
        assert admincenter_client.users["user-1@tenant1.es"].id == "id-1"
        assert admincenter_client.users["user-1@tenant1.es"].name == "User 1"

    def test_get_group_settings(self):
        admincenter_client = AdminCenter(set_mocked_microsoft365_provider())
        assert len(admincenter_client.groups) == 1
        assert admincenter_client.groups["id-1"].id == "id-1"
        assert admincenter_client.groups["id-1"].name == "Test"
        assert admincenter_client.groups["id-1"].visibility == "Public"

    def test_get_directory_roles(self):
        admincenter_client = AdminCenter(set_mocked_microsoft365_provider())
        assert (
            admincenter_client.directory_roles["GlobalAdministrator"].id
            == "id-directory-role"
        )
        assert (
            len(admincenter_client.directory_roles["GlobalAdministrator"].members) == 0
        )
