import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from prowler.providers.azure.models import AzureIdentityInfo
from prowler.providers.azure.services.entra.entra_service import (
    AuthorizationPolicy,
    ConditionalAccessPolicy,
    DirectoryRole,
    Entra,
    GroupSetting,
    NamedLocation,
    SecurityDefault,
    User,
)
from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_provider


async def mock_entra_get_users(_):
    return {
        DOMAIN: {
            "user-1@tenant1.es": User(id="id-1", name="User 1"),
        }
    }


async def mock_entra_get_authorization_policy(_):
    return {
        DOMAIN: AuthorizationPolicy(
            id="id-1",
            name="Name 1",
            description="Description 1",
            guest_invite_settings="none",
            guest_user_role_id=uuid4(),
        )
    }


async def mock_entra_get_group_settings(_):
    return {
        DOMAIN: {
            "id-1": GroupSetting(
                id="id-1",
                name="Test",
                template_id="id-group-setting",
                settings=[],
            )
        }
    }


async def mock_entra_get_security_default(_):
    return {
        DOMAIN: SecurityDefault(
            id="id-security-default",
            name="Test",
            is_enabled=True,
        )
    }


async def mock_entra_get_named_locations(_):
    return {
        DOMAIN: {
            "id-1": NamedLocation(
                id="id-1",
                name="Test",
                ip_ranges_addresses=[],
                is_trusted=False,
            )
        }
    }


async def mock_entra_get_directory_roles(_):
    return {
        DOMAIN: {
            "GlobalAdministrator": DirectoryRole(
                id="id-directory-role",
                members=[],
            )
        }
    }


async def mock_entra_get_conditional_access_policy(_):
    return {
        DOMAIN: {
            "id-1": ConditionalAccessPolicy(
                id="id-1",
                state="enabled",
                name="Test",
                users={"include": ["All"], "exclude": []},
                target_resources={
                    "include": ["797f4846-ba00-4fd7-ba43-dac1f8f63013"],
                    "exclude": [],
                },
                access_controls={"grant": ["MFA", "compliantDevice"], "block": []},
            )
        }
    }


@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_users",
    new=mock_entra_get_users,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_authorization_policy",
    new=mock_entra_get_authorization_policy,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_group_settings",
    new=mock_entra_get_group_settings,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_security_default",
    new=mock_entra_get_security_default,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_named_locations",
    new=mock_entra_get_named_locations,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_directory_roles",
    new=mock_entra_get_directory_roles,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra._get_conditional_access_policy",
    new=mock_entra_get_conditional_access_policy,
)
class Test_Entra_Service:
    def test_get_client(self):
        entra_client = Entra(
            set_mocked_azure_provider(identity=AzureIdentityInfo(tenant_domain=DOMAIN))
        )
        assert entra_client.clients[DOMAIN].__class__.__name__ == "GraphServiceClient"

    def test__get_subscriptions__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.subscriptions.__class__.__name__ == "dict"

    def test_get_users(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert len(entra_client.users) == 1
        assert entra_client.users[DOMAIN]["user-1@tenant1.es"].id == "id-1"
        assert entra_client.users[DOMAIN]["user-1@tenant1.es"].name == "User 1"
        assert entra_client.users[DOMAIN]["user-1@tenant1.es"].is_mfa_capable is False

    def test_get_authorization_policy(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.authorization_policy[DOMAIN].id == "id-1"
        assert entra_client.authorization_policy[DOMAIN].name == "Name 1"
        assert entra_client.authorization_policy[DOMAIN].description == "Description 1"
        assert not entra_client.authorization_policy[
            DOMAIN
        ].default_user_role_permissions

    def test_get_group_settings(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.group_settings[DOMAIN]["id-1"].name == "Test"
        assert (
            entra_client.group_settings[DOMAIN]["id-1"].template_id
            == "id-group-setting"
        )
        assert len(entra_client.group_settings[DOMAIN]["id-1"].settings) == 0

    def test_get_security_default(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.security_default[DOMAIN].id == "id-security-default"
        assert entra_client.security_default[DOMAIN].name == "Test"
        assert entra_client.security_default[DOMAIN].is_enabled

    def test_get_named_locations(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.named_locations[DOMAIN]["id-1"].name == "Test"
        assert (
            len(entra_client.named_locations[DOMAIN]["id-1"].ip_ranges_addresses) == 0
        )
        assert not entra_client.named_locations[DOMAIN]["id-1"].is_trusted

    def test_get_directory_roles(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert (
            entra_client.directory_roles[DOMAIN]["GlobalAdministrator"].id
            == "id-directory-role"
        )
        assert (
            len(entra_client.directory_roles[DOMAIN]["GlobalAdministrator"].members)
            == 0
        )

    def test_get_conditional_access_policy(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert len(entra_client.conditional_access_policy) == 1
        assert len(entra_client.conditional_access_policy[DOMAIN]) == 1
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"]
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"].name == "Test"
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"].state == "enabled"
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"].users[
            "include"
        ] == ["All"]
        assert (
            entra_client.conditional_access_policy[DOMAIN]["id-1"].users["exclude"]
            == []
        )
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"].target_resources[
            "include"
        ] == ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]
        assert (
            entra_client.conditional_access_policy[DOMAIN]["id-1"].target_resources[
                "exclude"
            ]
            == []
        )
        assert entra_client.conditional_access_policy[DOMAIN]["id-1"].access_controls[
            "grant"
        ] == ["MFA", "compliantDevice"]
        assert (
            entra_client.conditional_access_policy[DOMAIN]["id-1"].access_controls[
                "block"
            ]
            == []
        )


def test_azure_entra__get_users_handles_pagination():
    entra_service = Entra.__new__(Entra)

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

    users_builder = SimpleNamespace(
        get=AsyncMock(return_value=users_response_page_one),
        with_url=with_url_mock,
    )

    registration_details_response = SimpleNamespace(
        value=[
            SimpleNamespace(
                id="user-1",
                is_mfa_capable=True,
            ),
            SimpleNamespace(
                id="user-2",
                is_mfa_capable=True,
            ),
        ],
        odata_next_link=None,
    )

    registration_details_builder = SimpleNamespace(
        get=AsyncMock(return_value=registration_details_response),
        with_url=MagicMock(),
    )

    entra_service.clients = {
        "tenant-1": SimpleNamespace(
            users=users_builder,
            reports=SimpleNamespace(
                authentication_methods=SimpleNamespace(
                    user_registration_details=registration_details_builder
                )
            ),
        )
    }

    users = asyncio.run(entra_service._get_users())

    assert len(users["tenant-1"]) == 3
    assert users_builder.get.await_count == 1
    with_url_mock.assert_called_once_with("next-link")
    registration_details_builder.get.assert_awaited()
    registration_details_builder.with_url.assert_not_called()
    assert users["tenant-1"]["user-1"].is_mfa_capable is True
    assert users["tenant-1"]["user-2"].is_mfa_capable is True
    assert users["tenant-1"]["user-3"].is_mfa_capable is False
