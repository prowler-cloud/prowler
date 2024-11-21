from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.search.search_service import SearchService
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_search_service_not_publicly_accessible:
    def test_search_sevice_no_search_services(self):
        search_client = mock.MagicMock
        search_client.search_services = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible.search_client",
            new=search_client,
        ):
            from prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible import (
                search_service_not_publicly_accessible,
            )

            check = search_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_search_service_not_publicly_accessible_enabled(self):
        search_service_id = str(uuid4())
        search_service_name = "Test Search Service"
        search_client = mock.MagicMock
        search_client.search_services = {
            AZURE_SUBSCRIPTION_ID: [
                SearchService(
                    id=search_service_id,
                    name=search_service_name,
                    location="westeurope",
                    public_network_access=True,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible.search_client",
            new=search_client,
        ):
            from prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible import (
                search_service_not_publicly_accessible,
            )

            check = search_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Search Service {search_service_name} from subscription {AZURE_SUBSCRIPTION_ID} allows public access."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == search_service_name
            assert result[0].resource_id == search_service_id
            assert result[0].location == "westeurope"

    def test_search_service_not_publicly_accessible_disabled(self):
        search_service_id = str(uuid4())
        search_service_name = "Test Search Service"
        search_client = mock.MagicMock
        search_client.search_services = {
            AZURE_SUBSCRIPTION_ID: [
                SearchService(
                    id=search_service_id,
                    name=search_service_name,
                    location="westeurope",
                    public_network_access=False,
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible.search_client",
            new=search_client,
        ):
            from prowler.providers.azure.services.search.search_service_not_publicly_accessible.search_service_not_publicly_accessible import (
                search_service_not_publicly_accessible,
            )

            check = search_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Search Service {search_service_name} from subscription {AZURE_SUBSCRIPTION_ID} does not allows public access."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == search_service_name
            assert result[0].resource_id == search_service_id
            assert result[0].location == "westeurope"
