from unittest.mock import patch

from prowler.providers.azure.services.entra.entra_service import (
    AuthorizationPolicy,
    Entra,
    User,
)
from tests.providers.azure.azure_fixtures import DOMAIN, set_mocked_azure_audit_info


async def mock_entra_get_users(_):
    return {
        "user-1@tenant1.es": User(id="id-1", name="User 1"),
    }


async def mock_entra_get_authorization_policy(_):
    return AuthorizationPolicy(
        id="id-1",
        name="Name 1",
        description="Description 1",
        default_user_role_permissions=None,
        guest_invite_settings="everyone",
    )


@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_users__",
    new=mock_entra_get_users,
)
@patch(
    "prowler.providers.azure.services.entra.entra_service.Entra.__get_authorization_policy__",
    new=mock_entra_get_authorization_policy,
)
class Test_Entra_Service:
    def test__get_client__(self):
        entra_client = Entra(set_mocked_azure_audit_info())
        assert (
            entra_client.clients[DOMAIN]["v1"].__class__.__name__
            == "GraphServiceClient"
        )
        assert (
            entra_client.clients[DOMAIN]["beta"].__class__.__name__
            == "GraphServiceClient"
        )

    def test__get_subscriptions__(self):
        entra_client = Entra(set_mocked_azure_audit_info())
        assert entra_client.subscriptions.__class__.__name__ == "dict"

    def test__get_users__(self):
        entra_client = Entra(set_mocked_azure_audit_info())
        assert len(entra_client.users) == 1
        assert entra_client.users["user-1@tenant1.es"].id == "id-1"
        assert entra_client.users["user-1@tenant1.es"].name == "User 1"

    def test__get_authorization_policy__(self):
        entra_client = Entra(set_mocked_azure_audit_info())
        assert entra_client.authorization_policy.id == "id-1"
        assert entra_client.authorization_policy.name == "Name 1"
        assert entra_client.authorization_policy.description == "Description 1"
        assert not entra_client.authorization_policy.default_user_role_permissions
        assert entra_client.authorization_policy.guest_invite_settings == "everyone"
