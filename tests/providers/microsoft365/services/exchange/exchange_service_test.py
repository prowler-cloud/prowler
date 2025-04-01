from unittest.mock import patch

from prowler.providers.microsoft365.models import Microsoft365IdentityInfo
from prowler.providers.microsoft365.services.exchange.exchange_service import (
    Exchange,
    Organization,
)
from tests.providers.microsoft365.microsoft365_fixtures import (
    DOMAIN,
    set_mocked_microsoft365_provider,
)


def mock_exchange_get_organization_config(_):
    return Organization(audit_disabled=True, name="test", guid="test")


@patch(
    "prowler.providers.microsoft365.services.exchange.exchange_service.Exchange._get_organization_config",
    new=mock_exchange_get_organization_config,
)
class Test_Exchange_Service:
    def test_get_client(self):
        sharepoint_client = Exchange(
            set_mocked_microsoft365_provider(
                identity=Microsoft365IdentityInfo(tenant_domain=DOMAIN)
            )
        )
        assert sharepoint_client.client.__class__.__name__ == "GraphServiceClient"

    def test_get_organization_config(self):
        exchange_client = Exchange(set_mocked_microsoft365_provider())
        organization_config = exchange_client.organization_config
        assert organization_config.name == "test"
        assert organization_config.guid == "test"
        assert organization_config.audit_disabled is True
