from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.entra.entra_service import (
    AuthorizationPolicy,
    Entra,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


async def mock_entra_get_authorization_policy(_):
    return {
        "id-1": AuthorizationPolicy(
            id="id-1",
            name="Name 1",
            description="Description 1",
            default_user_role_permissions=None,
        )
    }


@patch(
    "prowler.providers.microsoft365.services.entra.entra_service.Entra._get_authorization_policy",
    new=mock_entra_get_authorization_policy,
)
class Test_Entra_Service:
    def test_get_client(self):
        admincenter_client = Entra(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert admincenter_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_authorization_policy(self):
        entra_client = Entra(set_mocked_microsoft365_provider())
        assert entra_client.authorization_policy["id-1"].id == "id-1"
        assert entra_client.authorization_policy["id-1"].name == "Name 1"
        assert entra_client.authorization_policy["id-1"].description == "Description 1"
        assert not entra_client.authorization_policy[
            "id-1"
        ].default_user_role_permissions
