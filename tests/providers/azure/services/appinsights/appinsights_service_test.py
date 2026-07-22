from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.appinsights.appinsights_service import (
    AppInsights,
    Component,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)


def mock_appinsights_get_components(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "app_id-1": Component(
                resource_id="/subscriptions/resource_id",
                resource_name="AppInsightsTest",
                location="westeurope",
                instrumentation_key="",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
    new=mock_appinsights_get_components,
)
class Test_AppInsights_Service:
    def test_get_client(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "ApplicationInsightsManagementClient"
        )

    def test__get_subscriptions__(self):
        app_insights = AppInsights(set_mocked_azure_provider())
        assert app_insights.subscriptions.__class__.__name__ == "dict"

    def test_get_components(self):
        appinsights = AppInsights(set_mocked_azure_provider())
        assert len(appinsights.components) == 1
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].resource_name
            == "AppInsightsTest"
        )
        assert (
            appinsights.components[AZURE_SUBSCRIPTION_ID]["app_id-1"].location
            == "westeurope"
        )


class Test_AppInsights_get_components:
    def test_get_components_no_resource_groups(self):
        mock_component = MagicMock()
        mock_component.app_id = "comp-app-id"
        mock_component.id = "/subscriptions/sub/rg/appinsights"
        mock_component.name = "ai-component"
        mock_component.location = "westeurope"
        mock_component.instrumentation_key = "ikey-123"

        mock_client = MagicMock()
        mock_client.components = MagicMock()
        mock_client.components.list.return_value = [mock_component]

        with patch(
            "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
            return_value={},
        ):
            app_insights = AppInsights(set_mocked_azure_provider())

        app_insights.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        app_insights.resource_groups = None

        result = app_insights._get_components()

        mock_client.components.list.assert_called_once()
        mock_client.components.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "comp-app-id" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_components_with_resource_group(self):
        mock_component = MagicMock()
        mock_component.app_id = "comp-app-id"
        mock_component.id = "/subscriptions/sub/rg/appinsights"
        mock_component.name = "ai-component"
        mock_component.location = "westeurope"
        mock_component.instrumentation_key = "ikey-123"

        mock_client = MagicMock()
        mock_client.components = MagicMock()
        mock_client.components.list_by_resource_group.return_value = [mock_component]

        with patch(
            "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
            return_value={},
        ):
            app_insights = AppInsights(set_mocked_azure_provider())

        app_insights.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        app_insights.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = app_insights._get_components()

        mock_client.components.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.components.list.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "comp-app-id" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_components_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.components = MagicMock()

        with patch(
            "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
            return_value={},
        ):
            app_insights = AppInsights(set_mocked_azure_provider())

        app_insights.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        app_insights.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = app_insights._get_components()

        mock_client.components.list_by_resource_group.assert_not_called()
        mock_client.components.list.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_components_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.components = MagicMock()
        mock_client.components.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
            return_value={},
        ):
            app_insights = AppInsights(set_mocked_azure_provider())

        app_insights.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        app_insights.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = app_insights._get_components()

        assert mock_client.components.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_components_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.components = MagicMock()
        mock_client.components.list_by_resource_group.return_value = []

        with patch(
            "prowler.providers.azure.services.appinsights.appinsights_service.AppInsights._get_components",
            return_value={},
        ):
            app_insights = AppInsights(set_mocked_azure_provider())

        app_insights.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        app_insights.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        app_insights._get_components()

        mock_client.components.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )
