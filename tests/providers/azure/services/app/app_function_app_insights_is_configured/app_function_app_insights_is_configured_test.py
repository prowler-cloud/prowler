from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_function_app_insights_is_configured:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured import (
                app_function_app_insights_is_configured,
            )

            app_client.functions = {}

            check = app_function_app_insights_is_configured()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscription_empty(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured import (
                app_function_app_insights_is_configured,
            )

            app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

            check = app_function_app_insights_is_configured()
            result = check.execute()
            assert len(result) == 0

    def test_app_function_no_app_insights(self):
        app_client = mock.MagicMock
        app_insights = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.app_client",
            new=app_client,
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.appinsights_client",
            new=app_insights,
        ):
            from prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured import (
                app_function_app_insights_is_configured,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp
            from prowler.providers.azure.services.appinsights.appinsights_service import (
                Component,
            )

            function_id = str(uuid4())

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    function_id: FunctionApp(
                        name="function1",
                        location="West Europe",
                        kind="functionapp,linux",
                        function_keys={},
                        enviroment_variables={},
                        identity=None,
                    )
                }
            }

            app_insights.components = {
                AZURE_SUBSCRIPTION_ID: {
                    "app_id-1": Component(
                        resource_id="component_id",
                        resource_name="component_name",
                        location="West Europe",
                        instrumentation_key="1234",
                    )
                }
            }

            check = app_function_app_insights_is_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Function 'function1' is not using Application Insights."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

    def test_app_function_using_app_insights(self):
        app_client = mock.MagicMock
        app_insights = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.app_client",
            new=app_client,
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured.appinsights_client",
            new=app_insights,
        ):
            from prowler.providers.azure.services.app.app_function_app_insights_is_configured.app_function_app_insights_is_configured import (
                app_function_app_insights_is_configured,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp
            from prowler.providers.azure.services.appinsights.appinsights_service import (
                Component,
            )

            function_id = str(uuid4())

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    function_id: FunctionApp(
                        name="function1",
                        location="West Europe",
                        kind="functionapp,linux",
                        function_keys={},
                        enviroment_variables={"APPINSIGHTS_INSTRUMENTATIONKEY": "1234"},
                        identity=None,
                    )
                }
            }

            app_insights.components = {
                AZURE_SUBSCRIPTION_ID: {
                    "app_id-1": Component(
                        resource_id="component_id",
                        resource_name="component_name",
                        location="West Europe",
                        instrumentation_key="1234",
                    )
                }
            }

            check = app_function_app_insights_is_configured()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Function 'function1' is using Application Insights."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"
