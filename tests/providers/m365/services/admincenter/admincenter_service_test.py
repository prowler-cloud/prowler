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


class Test_AdminCenter_Service_Type_Validation:
    def test_get_organization_config_with_string_data(self):
        """Test that _get_organization_config handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value="InvalidStringConfig",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            organization_config = admincenter_client.organization_config
            assert organization_config is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid organization config data type: <class 'str'> - InvalidStringConfig"
            )

            admincenter_client.powershell.close()

    def test_get_organization_config_with_mixed_data(self):
        """Test that _get_organization_config handles mixed data (dict + string) gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value=[
                    {
                        "Name": "Org1",
                        "Guid": "guid1",
                        "CustomerLockboxEnabled": True,
                    },  # Valid dict
                    "InvalidStringConfig",  # Invalid string
                ],
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return valid config from first item
            organization_config = admincenter_client.organization_config
            assert organization_config is not None
            assert organization_config.name == "Org1"
            assert organization_config.guid == "guid1"
            assert organization_config.customer_lockbox_enabled is True

            admincenter_client.powershell.close()

    def test_get_organization_config_with_empty_data(self):
        """Test that _get_organization_config handles empty data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value=[],  # Empty list
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            organization_config = admincenter_client.organization_config
            assert organization_config is None

            admincenter_client.powershell.close()

    def test_get_organization_config_with_none_data(self):
        """Test that _get_organization_config handles None data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value=None,  # None data
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid config was processed
            organization_config = admincenter_client.organization_config
            assert organization_config is None

            admincenter_client.powershell.close()

    def test_get_sharing_policy_with_string_data(self):
        """Test that _get_sharing_policy handles string data gracefully and logs warning"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_sharing_policy",
                return_value="InvalidStringPolicy",  # Return string instead of dict
            ),
            mock.patch("prowler.lib.logger.logger.warning") as mock_warning,
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            sharing_policy = admincenter_client.sharing_policy
            assert sharing_policy is None

            # Should log warning for the string item
            mock_warning.assert_called_once_with(
                "Skipping invalid sharing policy data type: <class 'str'> - InvalidStringPolicy"
            )

            admincenter_client.powershell.close()

    def test_get_sharing_policy_with_mixed_data(self):
        """Test that _get_sharing_policy handles mixed data (dict + string) gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_sharing_policy",
                return_value=[
                    {"Name": "Policy1", "Guid": "guid1", "Enabled": True},  # Valid dict
                    "InvalidStringPolicy",  # Invalid string
                ],
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return valid policy from first item
            sharing_policy = admincenter_client.sharing_policy
            assert sharing_policy is not None
            assert sharing_policy.name == "Policy1"
            assert sharing_policy.guid == "guid1"
            assert sharing_policy.enabled is True

            admincenter_client.powershell.close()

    def test_get_sharing_policy_with_empty_data(self):
        """Test that _get_sharing_policy handles empty data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_sharing_policy",
                return_value=[],  # Empty list
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            sharing_policy = admincenter_client.sharing_policy
            assert sharing_policy is None

            admincenter_client.powershell.close()

    def test_get_sharing_policy_with_none_data(self):
        """Test that _get_sharing_policy handles None data gracefully"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_sharing_policy",
                return_value=None,  # None data
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return None since no valid policy was processed
            sharing_policy = admincenter_client.sharing_policy
            assert sharing_policy is None

            admincenter_client.powershell.close()

    def test_get_organization_config_with_multiple_valid_configs(self):
        """Test that _get_organization_config takes first valid config when multiple are available"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_organization_config",
                return_value=[
                    {
                        "Name": "Org1",
                        "Guid": "guid1",
                        "CustomerLockboxEnabled": True,
                    },  # First valid config
                    {
                        "Name": "Org2",
                        "Guid": "guid2",
                        "CustomerLockboxEnabled": False,
                    },  # Second valid config (should be ignored)
                ],
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return first valid config
            organization_config = admincenter_client.organization_config
            assert organization_config is not None
            assert organization_config.name == "Org1"  # First config
            assert organization_config.guid == "guid1"  # First config
            assert (
                organization_config.customer_lockbox_enabled is True
            )  # First config value

            admincenter_client.powershell.close()

    def test_get_sharing_policy_with_multiple_valid_policies(self):
        """Test that _get_sharing_policy takes first valid policy when multiple are available"""
        with (
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.connect_exchange_online"
            ),
            mock.patch(
                "prowler.providers.m365.lib.powershell.m365_powershell.M365PowerShell.get_sharing_policy",
                return_value=[
                    {
                        "Name": "Policy1",
                        "Guid": "guid1",
                        "Enabled": True,
                    },  # First valid policy
                    {
                        "Name": "Policy2",
                        "Guid": "guid2",
                        "Enabled": False,
                    },  # Second valid policy (should be ignored)
                ],
            ),
        ):
            admincenter_client = AdminCenter(
                set_mocked_m365_provider(
                    identity=M365IdentityInfo(tenant_domain=DOMAIN)
                )
            )

            # Should return first valid policy
            sharing_policy = admincenter_client.sharing_policy
            assert sharing_policy is not None
            assert sharing_policy.name == "Policy1"  # First policy
            assert sharing_policy.guid == "guid1"  # First policy
            assert sharing_policy.enabled is True  # First policy value

            admincenter_client.powershell.close()
