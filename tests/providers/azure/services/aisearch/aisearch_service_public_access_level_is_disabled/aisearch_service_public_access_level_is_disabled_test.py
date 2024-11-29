from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.aisearch.aisearch_service import AISearchService
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_AISearch_service_not_publicly_accessible:
    def test_aisearch_sevice_no_aisearch_services(self):
        aisearch_client = mock.MagicMock
        aisearch_client.aisearch_services = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible.aisearch_client",
            new=aisearch_client,
        ):
            from prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible import (
                aisearch_service_not_publicly_accessible,
            )

            check = aisearch_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    def test_aisearch_service_not_publicly_accessible_enabled(self):
        aisearch_service_id = str(uuid4())
        aisearch_service_name = "Test AISearch Service"
        aisearch_client = mock.MagicMock
        aisearch_client.aisearch_services = {
            AZURE_SUBSCRIPTION_ID: {
                aisearch_service_id: AISearchService(
                    name=aisearch_service_name,
                    location="westeurope",
                    public_network_access=True,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible.aisearch_client",
            new=aisearch_client,
        ):
            from prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible import (
                aisearch_service_not_publicly_accessible,
            )

            check = aisearch_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AISearch Service {aisearch_service_name} from subscription {AZURE_SUBSCRIPTION_ID} allows public access."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == aisearch_service_name
            assert result[0].location == "westeurope"

    def test_aisearch_service_not_publicly_accessible_disabled(self):
        aisearch_service_id = str(uuid4())
        aisearch_service_name = "Test Search Service"
        aisearch_client = mock.MagicMock
        aisearch_client.aisearch_services = {
            AZURE_SUBSCRIPTION_ID: {
                aisearch_service_id: AISearchService(
                    name=aisearch_service_name,
                    location="westeurope",
                    public_network_access=False,
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible.aisearch_client",
            new=aisearch_client,
        ):
            from prowler.providers.azure.services.aisearch.aisearch_service_not_publicly_accessible.aisearch_service_not_publicly_accessible import (
                aisearch_service_not_publicly_accessible,
            )

            check = aisearch_service_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AISearch Service {aisearch_service_name} from subscription {AZURE_SUBSCRIPTION_ID} does not allows public access."
            )
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == aisearch_service_name
            assert result[0].resource_id == aisearch_service_id
            assert result[0].location == "westeurope"
