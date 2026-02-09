from unittest import mock

from prowler.providers.azure.services.appinsights.appinsights_service import Component
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_appinsights_ensure_is_configured:
    def test_appinsights_no_subscriptions(self):
        appinsights_client = mock.MagicMock
        appinsights_client.components = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured.appinsights_client",
                new=appinsights_client,
            ),
        ):
            from prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured import (
                appinsights_ensure_is_configured,
            )

            check = appinsights_ensure_is_configured()
            result = check.execute()
            assert len(result) == 0

    def test_no_appinsights(self):
        appinsights_client = mock.MagicMock
        appinsights_client.components = {AZURE_SUBSCRIPTION_ID: {}}
        appinsights_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured.appinsights_client",
                new=appinsights_client,
            ),
        ):
            from prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured import (
                appinsights_ensure_is_configured,
            )

            check = appinsights_ensure_is_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].status == "FAIL"
            assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
            assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
            assert (
                result[0].status_extended
                == f"There are no AppInsight configured in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_appinsights_configured(self):
        appinsights_client = mock.MagicMock
        appinsights_client.components = {
            AZURE_SUBSCRIPTION_ID: {
                "app_id-1": Component(
                    resource_id=f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/test-rg/providers/microsoft.insights/components/AppInsightsTest",
                    resource_name="AppInsightsTest",
                    location="westeurope",
                    instrumentation_key="",
                )
            }
        }
        appinsights_client.subscriptions = {
            AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_ID
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured.appinsights_client",
                new=appinsights_client,
            ),
        ):
            from prowler.providers.azure.services.appinsights.appinsights_ensure_is_configured.appinsights_ensure_is_configured import (
                appinsights_ensure_is_configured,
            )

            check = appinsights_ensure_is_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].status == "PASS"
            assert result[0].resource_id == f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
            assert result[0].resource_name == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "global"
            assert (
                result[0].status_extended
                == f"There is at least one AppInsight configured in subscription {AZURE_SUBSCRIPTION_ID}."
            )
