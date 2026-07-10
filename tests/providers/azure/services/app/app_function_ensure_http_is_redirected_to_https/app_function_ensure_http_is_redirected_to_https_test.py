from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_DISPLAY,
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)


class Test_app_function_ensure_http_is_redirected_to_https:
    def test_function_no_subscriptions(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        app_client.functions = {}

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

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_function_subscriptions_empty(self):
        app_client = mock.MagicMock
        app_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
        app_client.functions = {AZURE_SUBSCRIPTION_ID: {}}

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

            check = app_function_ensure_http_is_redirected_to_https()
            result = check.execute()
            assert len(result) == 0

    def test_function_http_not_redirected(self):
        resource_id = f"/subscriptions/{uuid4()}"
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

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    resource_id: FunctionApp(
                        id=resource_id,
                        name="function-1",
                        location="West Europe",
                        kind="functionapp",
                        function_keys=None,
                        environment_variables=None,
                        identity=None,
                        public_access=True,
                        vnet_subnet_id="",
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
                == f"HTTP is not redirected to HTTPS for Function app 'function-1' in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "function-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"

    def test_function_http_redirected(self):
        resource_id = f"/subscriptions/{uuid4()}"
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

            app_client.functions = {
                AZURE_SUBSCRIPTION_ID: {
                    resource_id: FunctionApp(
                        id=resource_id,
                        name="function-1",
                        location="West Europe",
                        kind="functionapp",
                        function_keys=None,
                        environment_variables=None,
                        identity=None,
                        public_access=True,
                        vnet_subnet_id="",
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
                == f"HTTP is redirected to HTTPS for Function app 'function-1' in subscription '{AZURE_SUBSCRIPTION_DISPLAY}'."
            )
            assert result[0].resource_name == "function-1"
            assert result[0].resource_id == resource_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].location == "West Europe"
