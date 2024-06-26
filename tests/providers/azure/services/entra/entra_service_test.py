from unittest.mock import patch

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
            default_user_role_permissions=None,
            guest_invite_settings="none",
            guest_user_role_id=None,
        )
    }


async def mock_entra_get_group_settings(_):
    return {
        DOMAIN: {
            "id-1": GroupSetting(
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
                access_controls={"grant": ["MFA"], "block": []},
            )
        }
    }


@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_users__",
    new=mock_entra_get_users,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_authorization_policy__",
    new=mock_entra_get_authorization_policy,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_group_settings__",
    new=mock_entra_get_group_settings,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_security_default__",
    new=mock_entra_get_security_default,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_named_locations__",
    new=mock_entra_get_named_locations,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_directory_roles__",
    new=mock_entra_get_directory_roles,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_conditional_access_policy__",
    new=mock_entra_get_conditional_access_policy,
)
class Test_Entra_Service:
    def test__get_client__(self):
        entra_client = Entra(
            set_mocked_azure_provider(identity=AzureIdentityInfo(tenant_domain=DOMAIN))
        )
        assert entra_client.clients[DOMAIN].__class__.__name__ == "GraphServiceClient"

    def test__get_subscriptions__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.subscriptions.__class__.__name__ == "dict"

    def test__get_users__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert len(entra_client.users) == 1
        assert entra_client.users[DOMAIN]["user-1@tenant1.es"].id == "id-1"
        assert entra_client.users[DOMAIN]["user-1@tenant1.es"].name == "User 1"
        assert (
            len(entra_client.users[DOMAIN]["user-1@tenant1.es"].authentication_methods)
            == 0
        )

    def test__get_authorization_policy__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.authorization_policy[DOMAIN].id == "id-1"
        assert entra_client.authorization_policy[DOMAIN].name == "Name 1"
        assert entra_client.authorization_policy[DOMAIN].description == "Description 1"
        assert not entra_client.authorization_policy[
            DOMAIN
        ].default_user_role_permissions

    def test__get_group_settings__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.group_settings[DOMAIN]["id-1"].name == "Test"
        assert (
            entra_client.group_settings[DOMAIN]["id-1"].template_id
            == "id-group-setting"
        )
        assert len(entra_client.group_settings[DOMAIN]["id-1"].settings) == 0

    def test__get_security_default__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.security_default[DOMAIN].id == "id-security-default"
        assert entra_client.security_default[DOMAIN].name == "Test"
        assert entra_client.security_default[DOMAIN].is_enabled

    def test__get_named_locations__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert entra_client.named_locations[DOMAIN]["id-1"].name == "Test"
        assert (
            len(entra_client.named_locations[DOMAIN]["id-1"].ip_ranges_addresses) == 0
        )
        assert not entra_client.named_locations[DOMAIN]["id-1"].is_trusted

    def test__get_directory_roles__(self):
        entra_client = Entra(set_mocked_azure_provider())
        assert (
            entra_client.directory_roles[DOMAIN]["GlobalAdministrator"].id
            == "id-directory-role"
        )
        assert (
            len(entra_client.directory_roles[DOMAIN]["GlobalAdministrator"].members)
            == 0
        )

    def test__get_conditional_access_policy__(self):
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
        ] == ["MFA"]
        assert (
            entra_client.conditional_access_policy[DOMAIN]["id-1"].access_controls[
                "block"
            ]
            == []
        )
