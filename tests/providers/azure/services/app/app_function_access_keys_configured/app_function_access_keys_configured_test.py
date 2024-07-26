from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_function_access_keys_configured:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured import (
                app_function_access_keys_configured,
            )

            app_client.functions = {}

            check = app_function_access_keys_configured()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscription_empty(self):
        app_client = mock.MagicMock
        app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured import (
                app_function_access_keys_configured,
            )

            check = app_function_access_keys_configured()
            result = check.execute()
            assert len(result) == 0

    def test_app_function_no_keys(self):
        app_client = mock.MagicMock
        app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured import (
                app_function_access_keys_configured,
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
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_access_keys_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Function function1 does not have function keys configured."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

    def test_app_function_using_functions_keys(self):
        app_client = mock.MagicMock
        app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_access_keys_configured.app_function_access_keys_configured import (
                app_function_access_keys_configured,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp

            function_id = str(uuid4())

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    function_id: FunctionApp(
                        name="function1",
                        location="West Europe",
                        kind="functionapp,linux",
                        function_keys={
                            "default": "key1",
                            "key2": "key2",
                        },
                        enviroment_variables={},
                        identity=None,
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_access_keys_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Function function1 has function keys configured."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"
