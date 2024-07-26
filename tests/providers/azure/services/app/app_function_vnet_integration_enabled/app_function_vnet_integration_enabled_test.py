from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_function_vnet_integration_enabled:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled import (
                app_function_vnet_integration_enabled,
            )

            app_client.functions = {}

            check = app_function_vnet_integration_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscription_empty(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled import (
                app_function_vnet_integration_enabled,
            )

            app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

            check = app_function_vnet_integration_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_app_function_vnet_integration_enabled(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled import (
                app_function_vnet_integration_enabled,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp

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
                        public_access=True,
                        vnet_subnet_id="vnet_subnet_id",
                        ftps_state="FtpsOnly",
                    )
                }
            }

            check = app_function_vnet_integration_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Function function1 has Virtual Network integration enabled with subnet 'vnet_subnet_id' enabled."
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"

    def test_app_function_vnet_integration_disabled(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_vnet_integration_enabled.app_function_vnet_integration_enabled import (
                app_function_vnet_integration_enabled,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp

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
                        public_access=True,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_vnet_integration_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Function function1 does not have virtual network integration enabled."
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
