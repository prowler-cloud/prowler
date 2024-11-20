from unittest.mock import patch

from prowler.providers.azure.services.search.search_service import Search, SearchService
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_storage_get_search_services(_):
    return {
        AZURE_SUBSCRIPTION_ID: [
            SearchService(
                id="id",
                name="name",
                location="westeurope",
                public_network_access="Enabled",
            )
        ]
    }


@patch(
    "prowler.providers.azure.services.search.search_service.Search._get_search_services",
    new=mock_storage_get_search_services,
)
class Test_Search_Service:
    def test_get_client(self):
        search = Search(set_mocked_azure_provider())
        assert (
            search.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "SearchManagementClient"
        )

    def test_get_search_services(self):
        search = Search(set_mocked_azure_provider())
        assert (
            search.search_services[AZURE_SUBSCRIPTION_ID][0].__class__.__name__
            == "SearchService"
        )
        assert search.search_services[AZURE_SUBSCRIPTION_ID][0].id == "id"
        assert search.search_services[AZURE_SUBSCRIPTION_ID][0].name == "name"
        assert search.search_services[AZURE_SUBSCRIPTION_ID][0].location == "westeurope"
        assert (
            search.search_services[AZURE_SUBSCRIPTION_ID][0].public_network_access
            == "Enabled"
        )
