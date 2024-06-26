from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_app_function_ftps_deployment_disabled:
    def test_no_subscriptions(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled import (
                app_function_ftps_deployment_disabled,
            )

            app_client.functions = {}

            check = app_function_ftps_deployment_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_subscription_empty(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled import (
                app_function_ftps_deployment_disabled,
            )

            app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

            check = app_function_ftps_deployment_disabled()
            result = check.execute()
            assert len(result) == 0

    def test_function_ftp_deployment_enabled(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled import (
                app_function_ftps_deployment_disabled,
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
                        identity=mock.MagicMock(type="SystemAssigned"),
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="AllAllowed",
                    )
                }
            }

            check = app_function_ftps_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Function function1 has FTP deployment enabled"
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_function_ftps_deployment_enabled(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled import (
                app_function_ftps_deployment_disabled,
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
                        identity=mock.MagicMock(type="SystemAssigned"),
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="FtpsOnly",
                    )
                }
            }

            check = app_function_ftps_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Function function1 has FTPS deployment enabled"
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_function_ftp_and_ftps_deployment_disabled(self):
        app_client = mock.MagicMock

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled.app_client",
            new=app_client,
        ):
            from prowler.providers.azure.services.app.app_function_ftps_deployment_disabled.app_function_ftps_deployment_disabled import (
                app_function_ftps_deployment_disabled,
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
                        identity=mock.MagicMock(type="SystemAssigned"),
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="Disabled",
                    )
                }
            }

            check = app_function_ftps_deployment_disabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Function function1 has FTP and FTPS deployment disabled"
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
