from unittest.mock import patch

from prowler.providers.azure.services.aisearch.aisearch_service import (
    AISearch,
    AISearchService,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_storage_get_aisearch_services(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "aisearch_service_id-1": AISearchService(
                name="name",
                location="westeurope",
                public_network_access=True,
            )
        }
    }


@patch(
    "prowler.providers.azure.services.aisearch.aisearch_service.AISearch._get_aisearch_services",
    new=mock_storage_get_aisearch_services,
)
class Test_AISearch_Service:
    def test_get_client(self):
        aisearch = AISearch(set_mocked_azure_provider())
        assert (
            aisearch.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "SearchManagementClient"
        )

    def test_get_aisearch_services(self):
        aisearch = AISearch(set_mocked_azure_provider())
        assert (
            aisearch.aisearch_services[AZURE_SUBSCRIPTION_ID][
                "aisearch_service_id-1"
            ].__class__.__name__
            == "AISearchService"
        )
        assert (
            aisearch.aisearch_services[AZURE_SUBSCRIPTION_ID][
                "aisearch_service_id-1"
            ].name
            == "name"
        )
        assert (
            aisearch.aisearch_services[AZURE_SUBSCRIPTION_ID][
                "aisearch_service_id-1"
            ].location
            == "westeurope"
        )
        assert aisearch.aisearch_services[AZURE_SUBSCRIPTION_ID][
            "aisearch_service_id-1"
        ].public_network_access
