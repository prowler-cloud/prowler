from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.aisearch.aisearch_service import (
    AISearch,
    AISearchService,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

RESOURCE_GROUP = "rg"
AISEARCH_SERVICE_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Search/searchServices/search1"


def mock_storage_get_aisearch_services(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "aisearch_service_id-1": AISearchService(
                id="aisearch_service_id-1",
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

    def test_get_aisearch_services_no_resource_groups(self):
        mock_service = MagicMock()
        mock_service.id = AISEARCH_SERVICE_ID
        mock_service.name = "search1"
        mock_service.location = "westeurope"
        mock_service.public_network_access = "Enabled"

        mock_client = MagicMock()
        mock_client.services.list_by_subscription.return_value = [mock_service]

        with patch(
            "prowler.providers.azure.services.aisearch.aisearch_service.AISearch._get_aisearch_services",
            return_value={},
        ):
            aisearch = AISearch(set_mocked_azure_provider(resource_groups=None))

        aisearch.clients = {AZURE_SUBSCRIPTION_NAME: mock_client}
        aisearch.resource_groups = None

        result = aisearch._get_aisearch_services()

        mock_client.services.list_by_subscription.assert_called_once()
        mock_client.services.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_NAME in result
        assert (
            result[AZURE_SUBSCRIPTION_NAME][AISEARCH_SERVICE_ID].public_network_access
            is True
        )

    def test_get_aisearch_services_with_resource_group(self):
        mock_service = MagicMock()
        mock_service.id = AISEARCH_SERVICE_ID
        mock_service.name = "search1"
        mock_service.location = "westeurope"
        mock_service.public_network_access = "Disabled"

        mock_client = MagicMock()
        mock_client.services.list_by_resource_group.return_value = [mock_service]

        with patch(
            "prowler.providers.azure.services.aisearch.aisearch_service.AISearch._get_aisearch_services",
            return_value={},
        ):
            aisearch = AISearch(set_mocked_azure_provider())

        aisearch.clients = {AZURE_SUBSCRIPTION_NAME: mock_client}
        aisearch.resource_groups = {AZURE_SUBSCRIPTION_NAME: [RESOURCE_GROUP]}

        result = aisearch._get_aisearch_services()

        mock_client.services.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.services.list_by_subscription.assert_not_called()
        assert (
            result[AZURE_SUBSCRIPTION_NAME][AISEARCH_SERVICE_ID].public_network_access
            is False
        )

    def test_get_aisearch_services_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()

        with patch(
            "prowler.providers.azure.services.aisearch.aisearch_service.AISearch._get_aisearch_services",
            return_value={},
        ):
            aisearch = AISearch(set_mocked_azure_provider())

        aisearch.clients = {AZURE_SUBSCRIPTION_NAME: mock_client}
        aisearch.resource_groups = {AZURE_SUBSCRIPTION_NAME: []}

        result = aisearch._get_aisearch_services()

        mock_client.services.list_by_resource_group.assert_not_called()
        mock_client.services.list_by_subscription.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_NAME] == {}
