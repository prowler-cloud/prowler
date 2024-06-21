from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_function_latest_runtime_version:
    def test_app_no_subscriptions(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version import (
                app_function_latest_runtime_version,
            )

            app_client.functions = {}

            check = app_function_latest_runtime_version()
            result = check.execute()
            assert len(result) == 0

    def test_app_subscription_empty(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version import (
                app_function_latest_runtime_version,
            )

            app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

            check = app_function_latest_runtime_version()
            result = check.execute()
            assert len(result) == 0

    def test_app_function_runtime_is_latest(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version import (
                app_function_latest_runtime_version,
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
                        enviroment_variables={"FUNCTIONS_EXTENSION_VERSION": "~4"},
                        identity=None,
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_latest_runtime_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "Function function1 is using the latest runtime."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

    def test_app_function_runtime_is_not_latest(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_latest_runtime_version.app_function_latest_runtime_version import (
                app_function_latest_runtime_version,
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
                        enviroment_variables={"FUNCTIONS_EXTENSION_VERSION": "2"},
                        identity=None,
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_latest_runtime_version()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "Function function1 is not using the latest runtime. The current runtime is '2' and should be '~4'."
            )
            assert result[0].resource_id == function_id
            assert result[0].resource_name == "function1"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"
