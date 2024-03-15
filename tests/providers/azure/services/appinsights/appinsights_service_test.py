from unittest.mock import patch

from prowler.providers.azure.services.appinsights.appinsights_service import (
    AppInsights,
    Component,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_provider,
)


def mock_appinsights_get_components(_):
    return {
        AZURE_SUBSCRIPTION: {
            "app_id-1": Component(
                resource_id="/subscriptions/resource_id",
                resource_name="AppInsightsTest",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights.__get_components__",
    new=mock_appinsights_get_components,
)
class Test_AppInsights_Service:
    def test__get_client__(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "ApplicationInsightsManagementClient"
        )

    def test__get_subscriptions__(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert app_insights.subscriptions.__class__.__name__ == "dict"

    def test__get_components__(self):
        appinsights = AppInsights(set_mocked_azure_provider())
        assert len(appinsights.components) == 1
        assert (
            appinsights.components[AZURE_SUBSCRIPTION]["app_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            appinsights.components[AZURE_SUBSCRIPTION]["app_id-1"].resource_name
            == "AppInsightsTest"
        )
