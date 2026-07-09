from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_app_function_ensure_http_is_redirected_to_https:
    def test_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https import (
                app_function_ensure_http_is_redirected_to_https,
            )

            app_client.functions = {}

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_subscription_empty(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https import (
                app_function_ensure_http_is_redirected_to_https,
            )

            app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_function_http_not_redirected_to_https(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https import (
                app_function_ensure_http_is_redirected_to_https,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp

            function_id = str(uuid4())

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    function_id: FunctionApp(
                        id=function_id,
                        name="function1",
                        location="West Europe",
                        kind="functionapp,linux",
                        function_keys={},
                        environment_variables={},
                        identity=mock.MagicMock(type="SystemAssigned"),
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="Disabled",
                        https_only=False,
                    )
                }
            }

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Function function1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} does not have HTTP redirected to HTTPS."
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID

    def test_function_http_redirected_to_https(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https.app_client",
                new=app_client,
            ),
        ):
            from prowler.providers.azure.services.app.app_function_ensure_http_is_redirected_to_https.app_function_ensure_http_is_redirected_to_https import (
                app_function_ensure_http_is_redirected_to_https,
            )
            from prowler.providers.azure.services.app.app_service import FunctionApp

            function_id = str(uuid4())

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    function_id: FunctionApp(
                        id=function_id,
                        name="function1",
                        location="West Europe",
                        kind="functionapp,linux",
                        function_keys={},
                        environment_variables={},
                        identity=mock.MagicMock(type="SystemAssigned"),
                        public_access=False,
                        vnet_subnet_id=None,
                        ftps_state="Disabled",
                        https_only=True,
                    )
                }
            }

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Function function1 from subscription {AZURE_SUBSCRIPTION_DISPLAY} has HTTP redirected to HTTPS."
            )
            assert result[0].resource_name == "function1"
            assert result[0].resource_id == function_id
            assert result[0].location == "West Europe"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
